package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	dataPort    = 7391
	ioTimeout   = 30 * time.Second
	pakeTimeout = 10 * time.Second
	maxConns    = 256

	// Empty daemons expire, commands restart them on demand.
	idleTimeout = 30 * time.Minute

	acceptRetryFloor   = 5 * time.Millisecond
	acceptRetryCeiling = time.Second

	peerPollInterval = 25 * time.Millisecond

	// Allow time for the first peer announcements after startup.
	peerWarmup = 5 * time.Second
)

type discovery interface {
	networkChanged()
	query()
}

type daemon struct {
	store   *store
	limiter *limiter
	peers   *peerTable
	net     *netFilter
	hostID  string
	port    int
	started time.Time

	// Set by startMDNS, nil when discovery is unavailable.
	mdns discovery

	// Stored as Unix seconds so updates remain atomic.
	lastUsed atomic.Int64
}

func (d *daemon) touch() {
	d.lastUsed.Store(time.Now().Unix())
}

func (d *daemon) idleFor() time.Duration {
	return time.Duration(time.Now().Unix()-d.lastUsed.Load()) * time.Second
}

// Never stop while a retrievable paste remains in memory.
func (d *daemon) shouldStop() bool {
	return len(d.store.list()) == 0 && d.idleFor() > idleTimeout
}

func runDaemon(ctx context.Context) error {
	cert, err := loadIdentity()
	if err != nil {
		return err
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{alpnProto},
	}
	data, err := listenData(ctx, tlsCfg)
	if err != nil {
		return err
	}
	defer func() { _ = data.Close() }()

	sock, err := listenControl(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = sock.Close() }()

	port, err := listenPort(data)
	if err != nil {
		return err
	}

	d := &daemon{
		store:   newStore(),
		limiter: newLimiter(),
		peers:   newPeerTable(),
		net:     newNetFilter(),
		hostID:  hostID(cert.Leaf.RawSubjectPublicKeyInfo),
		port:    port,
		started: time.Now(),
	}
	d.touch()

	// sweepLoop cancels this context when an empty daemon times out.
	ctx, stopIdle := context.WithCancel(ctx)
	defer stopIdle()

	// Direct fetches through --host do not depend on discovery.
	mdns, stopMDNS, err := startMDNS(ctx, d.peers, d.net, d.hostID, d.port)
	if err != nil {
		log.Printf("mdns: %v, tp get --host still works", err)
	}
	d.mdns = mdns
	defer stopMDNS()

	go d.sweepLoop(ctx, stopIdle)
	go d.netLoop(ctx)

	errc := make(chan error, 2)
	go func() { errc <- d.serveData(ctx, data) }()
	go func() { errc <- serveControl(sock, d.controlMux()) }()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// netLoop keeps discovery and data plane filtering in sync with interface
// changes. It remains active even if mDNS failed to start.
func (d *daemon) netLoop(ctx context.Context) {
	for waited(ctx, ifaceRefresh) {
		if !d.net.refresh() {
			continue
		}
		// Peers learned on the previous network are no longer reachable.
		d.peers.clear()
		if d.mdns != nil {
			d.mdns.networkChanged()
		}
	}
}

// listenData binds the fixed port, but publishes an ephemeral one through SRV
// when it is taken. serveData filters connections, so the listener can bind
// every interface.
func listenData(ctx context.Context, cfg *tls.Config) (net.Listener, error) {
	var lc net.ListenConfig
	for _, addr := range []string{fmt.Sprintf(":%d", dataPort), ":0"} {
		l, err := lc.Listen(ctx, "tcp", addr)
		if err != nil {
			continue
		}
		return tls.NewListener(l, cfg), nil
	}
	return nil, errors.New("data plane: no port available")
}

func listenPort(l net.Listener) (int, error) {
	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		return 0, errors.New("data plane: listener has no TCP address")
	}
	return addr.Port, nil
}

func (d *daemon) sweepLoop(ctx context.Context, stop func()) {
	t := time.NewTicker(sweepInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			d.store.sweep()
			d.limiter.sweep()
			d.peers.sweep()
			if d.shouldStop() {
				stop()
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

// serveData runs one PAKE exchange per TLS connection. All failures appear as
// the same connection close to the peer.
func (d *daemon) serveData(ctx context.Context, l net.Listener) error {
	sem := make(chan struct{}, maxConns)
	retry := acceptRetryFloor
	for {
		conn, err := l.Accept()
		if err != nil {
			// Go retries EINTR, EAGAIN and ECONNABORTED internally. Retry descriptor resource
			// exhaustion rather than dropping the in memory store.
			if ctx.Err() == nil && retryableAccept(err) {
				if !waited(ctx, retry) {
					return ctx.Err()
				}
				retry = min(retry*2, acceptRetryCeiling)
				continue
			}
			return err
		}
		retry = acceptRetryFloor

		// Reject VPN and tunnel interfaces excluded from discovery.
		if !d.net.serves(conn.LocalAddr()) {
			_ = conn.Close()
			continue
		}
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			_ = conn.Close()
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		go func() {
			defer func() {
				_ = conn.Close()
				<-sem
			}()
			// Handshake failures are expected when no local paste matches.
			_ = d.handshake(ctx, tlsConn)
		}()
	}
}

// Each candidate needs a fresh CPace exchange because its generator includes
// the connection's channel binding. At the candidate limit this takes about 32 ms.
func buildOffer(cands [][]byte, ci, sid, peerShare []byte) ([]*pakeSide, []byte, error) {
	if len(cands) > maxCandidates {
		return nil, nil, errProtocol
	}
	sides := make([]*pakeSide, len(cands))
	offer := make([]byte, 2, 2+len(cands)*(pointLen+macLen))
	offer[0], offer[1] = byte(len(cands)>>8), byte(len(cands)) //nolint:gosec // Bounded by the maxCandidates check above.
	for i, prs := range cands {
		sides[i] = newPakeSide(prs, ci, sid)
		if err := sides[i].finish(peerShare, sid); err != nil {
			return nil, nil, err
		}
		offer = append(offer, sides[i].share...)
		offer = append(offer, sides[i].serverTag()...)
	}
	return sides, offer, nil
}

func retryableAccept(err error) bool {
	return errors.Is(err, syscall.EMFILE) ||
		errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ENOMEM) ||
		errors.Is(err, syscall.ENOBUFS)
}

func (d *daemon) handshake(ctx context.Context, conn *tls.Conn) error {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return err
	}
	if !d.limiter.allowPeer(host) {
		return errProtocol
	}

	sid, err := d.openExchange(ctx, conn)
	if err != nil {
		return err
	}
	peerShare, err := readHello(conn)
	if err != nil {
		return err
	}

	// Count a guess only after sending an offer the client can test.
	if !d.limiter.allowExchange() {
		return errProtocol
	}

	cands := d.store.candidates()
	sides, offer, err := buildOffer(cands, channelID(d.hostID), sid, peerShare)
	if err != nil {
		return err
	}
	if err := writeFrame(conn, offer); err != nil {
		return err
	}

	// During fan out, hosts without a matching paste normally disconnect here.
	tag, err := readFrame(conn, macLen)
	if err != nil {
		return err
	}
	match := matchConfirmation(sides, tag)
	if match < 0 {
		d.limiter.fail(host)
		return errProtocol
	}

	body := d.store.take(cands[match])
	if body == nil {
		/// The candidate was a decoy or expired during the handshake.
		return errProtocol
	}
	sealed, err := sides[match].seal(body)
	if err != nil {
		return err
	}
	d.touch()
	_ = conn.SetDeadline(time.Now().Add(ioTimeout))
	return writeFrame(conn, sealed)
}

// openExchange completes TLS, checks ALPN and returns the channel binding used
// by the PAKE transcript.
func (d *daemon) openExchange(ctx context.Context, conn *tls.Conn) ([]byte, error) {
	if err := conn.SetDeadline(time.Now().Add(pakeTimeout)); err != nil {
		return nil, err
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if conn.ConnectionState().NegotiatedProtocol != alpnProto {
		return nil, errProtocol
	}
	return channelBinding(conn)
}

// rreadHello validates the wire version and returns the client's public share.
func readHello(conn *tls.Conn) ([]byte, error) {
	hello, err := readFrame(conn, helloLen)
	if err != nil {
		return nil, err
	}
	if len(hello) != helloLen || hello[0] != wireVersion {
		return nil, errProtocol
	}
	return hello[1:], nil
}

// The client cannot select a candidate directly. Scan every tag in constant time
// to prevent targeted guesses and avoid leaking the matching index.
func matchConfirmation(sides []*pakeSide, tag []byte) int {
	if len(tag) != macLen {
		return -1
	}
	match := -1
	for i, side := range sides {
		hit := subtle.ConstantTimeCompare(tag, side.clientTag())
		match = subtle.ConstantTimeSelect(hit, i, match)
	}
	return match
}

func serveControl(l net.Listener, h http.Handler) error {
	srv := &http.Server{
		Handler:      h,
		ReadTimeout:  ioTimeout,
		WriteTimeout: ioTimeout,
		ErrorLog:     log.New(io.Discard, "", 0),
	}
	return srv.Serve(l)
}

func (d *daemon) controlMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /pastes", d.handlePost)
	mux.HandleFunc("GET /pastes", d.handleList)
	mux.HandleFunc("GET /peers", d.handlePeers)
	mux.HandleFunc("DELETE /pastes/{prs}", d.handleDelete)
	mux.HandleFunc("DELETE /pastes", d.handleDeleteAll)
	return mux
}

func (d *daemon) handlePost(w http.ResponseWriter, r *http.Request) {
	d.touch()
	body, err := io.ReadAll(io.LimitReader(r.Body, maxPasteSize+1))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(body) > maxPasteSize {
		http.Error(w, "paste exceeds 1 MiB", http.StatusRequestEntityTooLarge)
		return
	}

	q := r.URL.Query()
	opts, err := parsePostOptions(q)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	newer := newCode
	if q.Get("code_style") == "digits" {
		newer = newDigitCode
	}
	expires := time.Now().Add(opts.ttl).Round(time.Second)
	for {
		code := newer()
		prs, err := derivePRS(code)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		err = d.store.add(&paste{
			Label:     q.Get("label"),
			Size:      len(body),
			ExpiresAt: expires,
			MaxGets:   opts.maxGets,
			prs:       prs,
			data:      body,
		})
		switch {
		case errors.Is(err, errCollision):
			continue
		case err != nil:
			http.Error(w, err.Error(), http.StatusInsufficientStorage)
			return
		}
		// Do not retain the code, the store contains only its derived password.
		writeJSON(w, map[string]any{"code": code, "expires_at": expires})
		return
	}
}

type postOptions struct {
	ttl     time.Duration
	maxGets int
}

func parsePostOptions(q url.Values) (postOptions, error) {
	opts := postOptions{ttl: defaultTTL}
	if v := q.Get("ttl"); v != "" {
		ttl, err := time.ParseDuration(v)
		if err != nil || ttl <= 0 || ttl > maxTTL {
			return opts, errors.New("ttl must be positive and at most 24h")
		}
		opts.ttl = ttl
	}
	if v := q.Get("max_gets"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return opts, errors.New("max_gets must be a non-negative integer")
		}
		opts.maxGets = n
	}
	return opts, nil
}

func (d *daemon) handleList(w http.ResponseWriter, _ *http.Request) {
	d.touch()
	writeJSON(w, map[string]any{
		"host_id": d.hostID,
		"port":    d.port,
		"pastes":  d.store.list(),
	})
}

// A newly started daemon may need a short wait for its first peer announcement.
func (d *daemon) handlePeers(w http.ResponseWriter, r *http.Request) {
	d.touch()
	if wait, err := time.ParseDuration(r.URL.Query().Get("wait")); err == nil && wait > 0 {
		d.waitForPeers(r.Context(), wait)
	}

	// Include the local daemon so same machine fetches do not depend on discovery.
	peers := append([]peer{{
		HostID:   d.hostID,
		Hostname: "this machine",
		Addr:     net.JoinHostPort("127.0.0.1", strconv.Itoa(d.port)),
		LastSeen: time.Now(),
	}}, d.peers.list()...)

	writeJSON(w, map[string]any{
		"peers":       peers,
		"diagnostic":  d.peers.diagnostic(),
		"packets":     d.peers.packets.Load(),
		"any_packets": d.peers.anyPackets.Load(),
		"uptime":      time.Since(d.started).Round(time.Second).String(),
		"interfaces":  ifaceNames(d.net.interfaces()),
	})
}

// Probe only during startup. Peers joining later announce themselves, so
// waiting after warmup would delay every fetch on an empty network.
func (d *daemon) waitForPeers(ctx context.Context, wait time.Duration) {
	if len(d.peers.list()) > 0 || time.Since(d.started) > peerWarmup {
		return
	}
	if d.mdns != nil {
		d.mdns.query()
	}
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		if !waited(ctx, peerPollInterval) {
			return
		}
		if len(d.peers.list()) > 0 {
			return
		}
	}
}

func (d *daemon) handleDelete(w http.ResponseWriter, r *http.Request) {
	d.touch()
	prs, err := hex.DecodeString(r.PathValue("prs"))
	if err != nil || !d.store.del(prs) {
		http.Error(w, "no such paste", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (d *daemon) handleDeleteAll(w http.ResponseWriter, _ *http.Request) {
	d.touch()
	d.store.clear()
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("control: %v", err)
	}
}

// Refuse a runtime directory accessible to other users before creating the
// control socket.
func listenControl(ctx context.Context) (net.Listener, error) {
	path, err := sockPath()
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if perm := fi.Mode().Perm(); perm != 0o700 {
		return nil, fmt.Errorf("%s: permissions are %04o, want 0700", dir, perm)
	}
	if c, err := new(net.Dialer).DialContext(ctx, "unix", path); err == nil {
		_ = c.Close()
		return nil, fmt.Errorf("%s: a daemon is already running", path)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = l.Close()
		return nil, err
	}
	return l, nil
}
