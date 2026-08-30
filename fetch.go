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

// Each non holder spends one exchange against a scrypt hardened 31 bit password
// and cannot retry offline, so trying many at once is safe as well as fast.
const (
	minFanOut   = 8
	maxFanOut   = 64
	dialTimeout = 2 * time.Second
)

// fanOut keeps a small network cheap and stops a large one turning into a
// queue. A 100 candidates eight at a time is 125 rounds of waiting.
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

// fetch runs the PAKE against every candidate in parallel and returns the first
// paste that comes back. Everyone else fails key confirmation and learns
// nothing, down to whether they were the one being asked.
func fetch(ctx context.Context, prs []byte, cands []candidate) ([]byte, error) {
	// Pinned hosts first. A previously fetched host is the likeliest holder and
	// its certificate can be checked directly.
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

	// Pinning this machine would turn a regenerated identity key into a mismatch
	// warning against itself.
	if !isLoopback(c.addr) {
		// The paste is already in hand and the fetch has been counted, so a
		// failed pin write cannot abort.
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

// clientTLSConfig checks the pin when there is one. No CA is involved: TLS
// supplies confidentiality and the exporter, and authentication comes from the
// PAKE.
//
// The check hangs off VerifyConnection rather than VerifyPeerCertificate because
// a resumed handshake carries no Certificate message and would skip the latter,
// leaving the pin unenforced.
func clientTLSConfig(c candidate) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		//nolint:gosec // The PAKE authenticates the peer, so no CA is involved.
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

// checkPin reports whether cert belongs to the host this candidate names and
// whether its key still matches a recorded pin.
func (c candidate) checkPin(cert *x509.Certificate) error {
	if c.pin == nil {
		return nil
	}
	// The host ID is a hash of the key, so a certificate hashing to a different
	// one is a different machine. Anyone on the LAN can advertise another host's
	// ID, so this is a misdirected candidate rather than a rotated key.
	if hostID(cert.RawSubjectPublicKeyInfo) != c.hostID {
		return errNoMatch
	}
	if got := spkiHash(cert); got != c.pin.SPKI {
		return &pinMismatchError{hostID: c.hostID, got: got, want: c.pin.SPKI}
	}
	return nil
}

// exchange runs the four message PAKE and returns the decrypted paste.
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

// matchOffer finds the paste this code belongs to and fills in the session key.
// The server answered for every paste it holds and exactly one of those
// confirmations can verify.
//
// Every candidate is scanned even after a match. Stopping early makes the gap
// before the confirmation message scale with the matching index, a scalar
// multiplication apiece, and that is visible to anyone watching packet timing.
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
		// Not the holder. Hanging up without confirming leaves the peer's
		// counters untouched.
		return errNoMatch
	}
	return nil
}
