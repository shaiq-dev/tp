package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"sync"
	"time"
)

// Each candidate gets one online PAKE attempt against the scrypt hardened
// 31 bit code. Fan out does not create an offline guessing path.
const (
	minFanOut   = 8
	maxFanOut   = 64
	dialTimeout = 2 * time.Second
)

// Use enough concurrent connections to keep small networks quick without
// flooding larger ones.
func fanOut(candidates int) int {
	return min(maxFanOut, max(minFanOut, candidates/4))
}

type candidate struct {
	hostID   string
	hostname string
	addr     string
	pin      *pin
}

type pinMismatchError struct {
	hostID string
	got    string
	want   string
}

func (e *pinMismatchError) Error() string {
	return fmt.Sprintf("host %s presented key %s but %s is pinned, refusing to continue", e.hostID, e.got, e.want)
}

// fetch tries candidates concurrently and returns the first authenticated paste.
// Non holders learn only that PAKE confirmation failed.
func fetch(ctx context.Context, prs []byte, cands []candidate) ([]byte, error) {
	// Try pinned hosts first, a previous sender is more likely to hold the paste.
	cands = slices.Clone(cands)
	slices.SortStableFunc(cands, func(a, b candidate) int {
		switch {
		case a.pin != nil && b.pin == nil:
			return -1
		case a.pin == nil && b.pin != nil:
			return 1
		default:
			return 0
		}
	})

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		body []byte
		err  error
	}
	results := make(chan result, len(cands))
	sem := make(chan struct{}, fanOut(len(cands)))
	var wg sync.WaitGroup

	for _, c := range cands {
		wg.Go(func() {
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			body, err := fetchFrom(ctx, prs, c)
			results <- result{body, err}
		})
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	var pinErr error
	for r := range results {
		if r.err == nil {
			return r.body, nil
		}
		if _, ok := errors.AsType[*pinMismatchError](r.err); ok {
			pinErr = r.err
		}
	}
	if pinErr != nil {
		return nil, pinErr
	}
	return nil, errNoMatch
}

func fetchFrom(ctx context.Context, prs []byte, c candidate) ([]byte, error) {
	dialer := &net.Dialer{Timeout: dialTimeout}
	raw, err := dialer.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = raw.Close() }()

	conn := tls.Client(raw, clientTLSConfig(c))
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(pakeTimeout)); err != nil {
		return nil, err
	}

	state := conn.ConnectionState()
	if state.NegotiatedProtocol != alpnProto {
		return nil, fmt.Errorf("%w: peer speaks %q, not %q", errProtocol, state.NegotiatedProtocol, alpnProto)
	}
	if len(state.PeerCertificates) == 0 {
		return nil, errProtocol
	}
	leaf := state.PeerCertificates[0]
	serverID := hostID(leaf.RawSubjectPublicKeyInfo)

	body, err := exchange(conn, prs, serverID)
	if err != nil {
		return nil, err
	}

	// Do not pin the local daemon, a regenerated identity would look like a
	// remote key change.
	if !isLoopback(c.addr) {
		// TThe fetch has succeeded, so a pin cache failure is non fatal.
		if err := savePin(serverID, pin{SPKI: spkiHash(leaf), Hostname: c.hostname}); err != nil {
			fmt.Fprintln(os.Stderr, "tp: could not update the pin cache:", err)
		}
	}
	return body, nil
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// TLS provides encryption and channel binding, PAKE authenticates unpinned
// peers, while recorded SPKI pins authenticate known hosts.
//
// VerifyConnection also runs for resumed sessions, where VerifyPeerCertificate
// may be skipped.
func clientTLSConfig(c candidate) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		//nolint:gosec // Peer authentication is provided by PAKE or an SPKI pin.
		InsecureSkipVerify: true,
		NextProtos:         []string{alpnProto},
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errProtocol
			}
			return c.checkPin(state.PeerCertificates[0])
		},
	}
}

// checkPin verifies that a pinned candidate still presents the expected host
// identity and key.
func (c candidate) checkPin(cert *x509.Certificate) error {
	if c.pin == nil {
		return nil
	}
	// A host ID is derived from its key. A mismatch means discovery sent us to
	// another machine, not that the pinned host rotated its key.
	if hostID(cert.RawSubjectPublicKeyInfo) != c.hostID {
		return errNoMatch
	}
	if got := spkiHash(cert); got != c.pin.SPKI {
		return &pinMismatchError{hostID: c.hostID, got: got, want: c.pin.SPKI}
	}
	return nil
}

// exchange completes the four message PAKE and decrypts the returned paste.
func exchange(conn *tls.Conn, prs []byte, serverID string) ([]byte, error) {
	sid, err := channelBinding(conn)
	if err != nil {
		return nil, err
	}
	side := newPakeSide(prs, channelID(serverID), sid)

	if err := writeFrame(conn, append([]byte{wireVersion}, side.share...)); err != nil {
		return nil, err
	}
	offer, err := readFrame(conn, maxOfferLen)
	if err != nil {
		return nil, err
	}
	if err := matchOffer(side, sid, offer); err != nil {
		return nil, err
	}
	if err := writeFrame(conn, side.clientTag()); err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(ioTimeout)); err != nil {
		return nil, err
	}
	sealed, err := readFrame(conn, maxFrame)
	if err != nil {
		return nil, err
	}
	return side.open(sealed)
}

// matchOffer checks every server candidate and keeps the session key for the
// matching paste. Scanning the full offer prevents response timing from leaking
// the candidate's index.
func matchOffer(side *pakeSide, sid, offer []byte) error {
	if len(offer) < 2 {
		return errProtocol
	}
	n := int(offer[0])<<8 | int(offer[1])
	if len(offer) != 2+n*(pointLen+macLen) {
		return errProtocol
	}
	side.sk = nil
	for i := range n {
		off := 2 + i*(pointLen+macLen)
		share := offer[off : off+pointLen]
		tag := offer[off+pointLen : off+pointLen+macLen]
		k, err := scalarMultVfy(side.scalar, share)
		if err != nil {
			continue
		}
		sk := sessionKey(sid, k, side.share, share)
		if macEqual(tag, confirm(sk, "tp/confirm/server")) {
			side.sk = sk
		}
	}
	if side.sk == nil {
		// Do not confirm a non holder or charge any of its pastes.
		return errNoMatch
	}
	return nil
}
