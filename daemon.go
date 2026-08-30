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

	// An empty daemon still announces itself, so it stops. The next command
	// starts another one.
	idleTimeout = 30 * time.Minute

	acceptRetryFloor   = 5 * time.Millisecond
	acceptRetryCeiling = time.Second

	peerPollInterval = 25 * time.Millisecond

	// peerWarmup is how long after start a daemon is still expecting its first
	// answers. Past it an empty table means an empty network, and waiting would
	// cost every fetch on a single machine.
	peerWarmup = 5 * time.Second
)

type daemon struct {
	store   *store
	limiter *limiter
	peers   *peerTable
	net     *netFilter
	hostID  string
	port    int
	started time.Time

	// onNetChange and probe are filled in by startMDNS. Both stay nil when mDNS
	// fails to start, which leaves the daemon working without discovery.
	onNetChange func()
	probe       func()

	// lastUsed holds a Unix second, not a Time, so it fits an atomic.
	lastUsed atomic.Int64
}

func (d *daemon) touch() { d.lastUsed.Store(time.Now().Unix()) }

func (d *daemon) idleFor() time.Duration {
	return time.Duration(time.Now().Unix()-d.lastUsed.Load()) * time.Second
}

// shouldStop requires an empty store, so stopping cannot lose a paste that
// someone is holding a code for.
func (d *daemon) shouldStop() bool {
	return len(d.store.list()) == 0 && d.idleFor() > idleTimeout
}

// runDaemon brings up the control socket, the TLS data plane and mDNS, then
// blocks until one of them fails.
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

	port, ok := listenPort(data)
	if !ok {
		return errors.New("data plane: listener has no TCP address")
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

	// sweepLoop cancels this when the daemon goes idle, so everything below
	// unwinds on that as well as on the user's signal.
	ctx, stopIdle := context.WithCancel(ctx)
	defer stopIdle()

	// tp get --host works without discovery, so a failure here is not fatal.
	stopMDNS, err := startMDNS(ctx, d)
	if err != nil {
		log.Printf("mdns: %v, tp get --host still works", err)
	}
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

// netLoop re-reads the usable interfaces. It runs from the daemon rather than
// from the responder because the data plane filters on the same set, and mDNS
// may never have started on a machine that booted with its wifi off.
func (d *daemon) netLoop(ctx context.Context) {
	for sleep(ctx, ifaceRefresh) {
		if !d.net.refresh() {
			continue
		}
		// Changed addresses mean a different network, where nothing learned on
		// the old one is reachable.
		d.peers.clear()
		if d.onNetChange != nil {
			d.onNetChange()
		}
	}
}

// sleep reports false when ctx is cancelled before d elapses.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// listenData binds the fixed port, falling back to an ephemeral one published
// through SRV when it is taken. Binding every interface is deliberate:
// serveData refuses connections that did not arrive on one tp advertises on.
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

func listenPort(l net.Listener) (int, bool) {
	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		return 0, false
	}
	return addr.Port, true
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

// serveData accepts TLS connections and runs one PAKE exchange on each. Every
// failure closes the connection identically, so a wrong code, a burned paste and
// an absent paste are indistinguishable from outside.
func (d *daemon) serveData(ctx context.Context, l net.Listener) error {
	sem := make(chan struct{}, maxConns)
	retry := acceptRetryFloor
	for {
		conn, err := l.Accept()
		if err != nil {
			// Go retries EINTR, EAGAIN and ECONNABORTED internally, so what
			// reaches here is mostly descriptor exhaustion. Returning would
			// unwind runDaemon and drop every paste held in memory.
			if ctx.Err() == nil && retryableAccept(err) {
				if !sleep(ctx, retry) {
					return ctx.Err()
				}
				retry = min(retry*2, acceptRetryCeiling)
				continue
			}
			return err
		}
		retry = acceptRetryFloor

		// The listener binds every interface, so without this pastes stay
		// reachable over VPN and tunnel links that mDNS deliberately skips.
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
			// Not logged. The error is derived from peer input and would tell
			// the peer which step it failed at.
			_ = d.handshake(ctx, tlsConn)
		}()
	}
}

// buildOffer runs one CPace instance per candidate, a scalar multiplication
// each and around 32 ms at the paste cap. The generator depends on the per
// connection channel binding, so none of it can be precomputed.
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

	// The offer is the oracle, so a guess is counted here and not at accept.
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

	// A client that verifies no server tag hangs up here, which is the normal
	// outcome of a fan out reaching a host that holds nothing.
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
		// A decoy, or a paste that expired mid handshake.
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

// openExchange completes TLS, confirms the peer speaks this protocol, and
// returns the channel binding the PAKE transcript is tied to.
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

// readHello returns the client's public share.
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

// matchConfirmation returns the index of the candidate the client's tag belongs
// to, or a negative number for none. The client sends no index, since letting it
// name one would let any peer aim a failed confirmation at a paste it knows
// nothing about. The search runs in constant time so it leaks no index either.
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
		// The only time the daemon holds the code. Only the derived password
		// is stored.
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

// handlePeers waits for the first announcements when the wait query parameter is
// set. A daemon started by the calling command has an empty table for a few
// hundred milliseconds, which otherwise reads as an empty network.
func (d *daemon) handlePeers(w http.ResponseWriter, r *http.Request) {
	d.touch()
	if wait, err := time.ParseDuration(r.URL.Query().Get("wait")); err == nil && wait > 0 {
		d.waitForPeers(r.Context(), wait)
	}

	// This machine is a candidate for its own fetches, so posting and getting on
	// one machine works without any peers at all.
	peers := append([]peer{{
		HostID:   d.hostID,
		Hostname: "this machine",
		Addr:     net.JoinHostPort("127.0.0.1", strconv.Itoa(d.port)),
		LastSeen: time.Now(),
	}}, d.peers.list()...)

	writeJSON(w, map[string]any{
		"peers":      peers,
		"diagnostic": d.peers.diagnostic(),
		"packets":    d.peers.packets.Load(),
		"uptime":     time.Since(d.started).Round(time.Second).String(),
		"interfaces": ifaceNames(d.net.interfaces()),
	})
}

// waitForPeers probes and waits only during warmup. A daemon up longer than
// peerWarmup with an empty table is on an empty network, and a machine joining
// later announces itself unsolicited, so waiting past that point would slow
// every fetch for nothing.
func (d *daemon) waitForPeers(ctx context.Context, wait time.Duration) {
	if len(d.peers.list()) > 0 || time.Since(d.started) > peerWarmup {
		return
	}
	if d.probe != nil {
		d.probe()
	}
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		if !sleep(ctx, peerPollInterval) {
			return
		}
		if len(d.peers.list()) > 0 {
			return
		}
	}
}

// handleDelete takes the hex derived PAKE password, not the code. The CLI
// derives it so a spoken code never crosses the control socket.
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

// listenControl binds the unix socket. Permissions that would admit another
// local user abort the daemon rather than being corrected, since by then the
// socket has already been exposed.
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

func dataDir() (string, error) {
	return xdgDir("XDG_DATA_HOME", ".local", "share")
}

func sockPath() (string, error) {
	dir, err := xdgDir("XDG_RUNTIME_DIR", ".local", "state")
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "sock"), nil
}

func xdgDir(env string, fallback ...string) (string, error) {
	dir, err := xdgPath(env, fallback...)
	if err != nil {
		return "", err
	}
	return dir, os.MkdirAll(dir, 0o700) //nolint:gosec // dir comes from the user's own XDG environment.
}

// xdgPath is xdgDir without the side effect, for code that wants to know where
// something would be rather than to use it.
func xdgPath(env string, fallback ...string) (string, error) {
	dir := os.Getenv(env)
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(append([]string{home}, fallback...)...)
	}
	return filepath.Join(dir, "tp"), nil
}
