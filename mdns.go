package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// Advertise one `_tp._tcp` instance per machine. mDNS maps a host ID to a candidate
// address, PAKE authenticates the peer.
//
// Periodic announcements keep multicast traffic linear with the number of machines.
// Query and response discovery approaches quadratic traffic and wifi carries multicast
// at its slowest rate.
const (
	mdnsService = "_tp._tcp.local."
	mdnsPort    = 5353

	announceInterval = 10 * time.Minute
	peerLifetime     = 25 * time.Minute
	mdnsTTL          = uint32(peerLifetime / time.Second)
	browseWhenEmpty  = time.Minute

	// Stagger replies so one query does not make every host transmit at once.
	answerDelayFloor   = 20 * time.Millisecond
	answerDelayCeiling = 120 * time.Millisecond
	answerMinGap       = time.Second

	legacyBurst     = 5
	legacyPerSecond = 5

	quietPeriod = 15 * time.Second
)

// Repeat startup traffic to tolerate packet loss without waiting for the next
// announcement interval.
var startupBurst = []time.Duration{0, time.Second, 3 * time.Second}

var mdnsGroup = net.IPv4(224, 0, 0, 251)

// classFlush sets the RFC 6762 cache flush bit for records owned by one machine.
// The shared service PTR does not use it.
const classFlush = dnsmessage.ClassINET | 0x8000

type peer struct {
	HostID   string    `json:"host_id"`
	Hostname string    `json:"hostname"`
	Addr     string    `json:"addr"`
	LastSeen time.Time `json:"last_seen"`
}

// Advertise the wire version so incompatible peers are skipped before dialing.
const txtVersion = "1"

type peerTable struct {
	mu sync.Mutex
	m  map[string]peer

	// packets excludes local traffic, anyPackets includes it. Receiving our own
	// mDNS traffic proves the multicast socket works even when no peers exist.
	packets    atomic.Int64
	anyPackets atomic.Int64
	started    time.Time
}

func newPeerTable() *peerTable {
	return &peerTable{m: make(map[string]peer), started: time.Now()}
}

func (t *peerTable) put(p peer) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.m[p.HostID] = p
}

func (t *peerTable) drop(hostID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.m, hostID)
}

func (t *peerTable) clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	clear(t.m)
}

func (t *peerTable) list() []peer {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]peer, 0, len(t.m))
	for _, p := range t.m {
		out = append(out, p)
	}
	return out
}

func (t *peerTable) sweep() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for id, p := range t.m {
		if time.Since(p.LastSeen) > peerLifetime {
			delete(t.m, id)
		}
	}
}

// diagnostic waits through startup before reporting that no multicast arrived.
func (t *peerTable) diagnostic() string {
	if time.Since(t.started) < quietPeriod || t.anyPackets.Load() > 0 {
		return ""
	}
	msg := "no multicast traffic is arriving, so discovery cannot work.\n"
	if advice := discoveryAdvice(); len(advice) > 0 {
		return msg + strings.Join(advice, "\n") + "\nRun tp doctor for the full picture."
	}
	return msg + "This network blocks client to client traffic. Guest, hotel and " +
		"enterprise wifi usually do. Run tp doctor for the full picture."
}

// mDNSResponder on macOS or Avahi on Linux may already own UDP 5353. Set SO_REUSEADDR and
// SO_REUSEPORT before binding so tp can listen alongside them.
func listenMDNS(ctx context.Context) (*ipv4.PacketConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var setErr error
		err := c.Control(func(fd uintptr) {
			for _, opt := range []int{unix.SO_REUSEADDR, unix.SO_REUSEPORT} {
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, opt, 1); err != nil {
					setErr = err
					return
				}
			}
		})
		if err != nil {
			return err
		}
		return setErr
	}}
	c, err := lc.ListenPacket(ctx, "udp4", fmt.Sprintf("0.0.0.0:%d", mdnsPort))
	if err != nil {
		return nil, err
	}
	return ipv4.NewPacketConn(c), nil
}

type responder struct {
	peers  *peerTable
	net    *netFilter
	hostID string
	port   int
	conn   *ipv4.PacketConn

	// instance is <hostID>._tp._tcp.local. and target is <hostID>.local.
	instance string
	target   string
	hostname string

	// Multicast memberships keyed by interface name.
	joinedMu sync.Mutex
	joined   map[string]bool

	// SetMulticastInterface changes socket wide state, so serialize sends.
	sendMu sync.Mutex

	answerMu      sync.Mutex
	answerPending bool
	lastAnswer    time.Time

	// Rate limit legacy unicast replies. Their spoofable source and larger
	// response would otherwise make this socket useful for reflection.
	legacyMu     sync.Mutex
	legacyBucket bucket

	// onSend intercepts socket writes in tests.
	onSend func([]byte)
}

// startMDNS returns a stop function that sends a goodbye before closing the socket.
func startMDNS(ctx context.Context, peers *peerTable, nf *netFilter, hostID string, port int) (*responder, func(), error) {
	noop := func() {}
	conn, err := listenMDNS(ctx)
	if err != nil {
		return nil, noop, err
	}
	if err := conn.SetMulticastLoopback(true); err != nil {
		_ = conn.Close()
		return nil, noop, err
	}

	name, _ := os.Hostname()
	r := &responder{
		peers:    peers,
		net:      nf,
		hostID:   hostID,
		port:     port,
		conn:     conn,
		joined:   make(map[string]bool),
		instance: hostID + "." + mdnsService,
		target:   hostID + ".local.",
		hostname: strings.TrimSuffix(name, ".local"),
	}
	// Starting without a usable interface (machine that booted with its wifi off) is valid,
	// netLoop retries after the network changes.
	_ = r.syncGroups()

	go r.readLoop()
	go r.announceLoop(ctx)
	go r.browseLoop(ctx)

	return r, func() {
		// Remove this address from peer caches before closing the socket.
		r.send(r.buildRecords(0))
		_ = conn.Close()
	}, nil
}

// syncGroups joins new interfaces and forgets those that disappeared. A removed
// interface takes its multicast membership with it.
func (r *responder) syncGroups() error {
	ifaces := r.net.interfaces()

	r.joinedMu.Lock()
	defer r.joinedMu.Unlock()

	seen := make(map[string]bool, len(ifaces))
	for _, ifi := range ifaces {
		seen[ifi.Name] = true
		if r.joined[ifi.Name] {
			continue
		}
		if err := r.conn.JoinGroup(&ifi, &net.UDPAddr{IP: mdnsGroup}); err != nil {
			continue
		}
		r.joined[ifi.Name] = true
	}
	for name := range r.joined {
		if !seen[name] {
			delete(r.joined, name)
		}
	}
	if len(r.joined) == 0 {
		return errNoInterface
	}
	return nil
}

var errNoInterface = errors.New("no usable multicast interface")

// networkChanged runs after netLoop clears peers from the previous network.
func (r *responder) networkChanged() {
	if err := r.syncGroups(); err != nil {
		return
	}
	r.send(r.buildRecords(mdnsTTL))
	r.query()
}

// jitter varies an interval by ±25% to keep hosts from transmitting in lockstep.
func jitter(d time.Duration) time.Duration {
	return d*3/4 + time.Duration(randIndex(int(d/2)))
}

// announceLoop sends startup retries followed by periodic announcements.
func (r *responder) announceLoop(ctx context.Context) {
	for _, delay := range startupBurst {
		if !waited(ctx, delay) {
			return
		}
		r.send(r.buildRecords(mdnsTTL))
	}
	for waited(ctx, jitter(announceInterval)) {
		r.send(r.buildRecords(mdnsTTL))
	}
}

// browseLoop queries during startup and later only when no peers are known.
func (r *responder) browseLoop(ctx context.Context) {
	for _, delay := range startupBurst {
		if !waited(ctx, delay) {
			return
		}
		r.query()
	}
	for waited(ctx, browseWhenEmpty) {
		if len(r.peers.list()) == 0 {
			r.query()
		}
	}
}

func (r *responder) query() {
	msg := dnsmessage.Message{Questions: []dnsmessage.Question{{
		Name:  dnsmessage.MustNewName(mdnsService),
		Type:  dnsmessage.TypePTR,
		Class: dnsmessage.ClassINET,
	}}}
	buf, err := msg.Pack()
	if err != nil {
		return
	}
	r.send(buf)
}

func (r *responder) readLoop() {
	buf := make([]byte, 9000)
	for {
		n, _, src, err := r.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		r.peers.anyPackets.Add(1)
		if !r.isOwn(src) {
			r.peers.packets.Add(1)
		}
		r.handle(buf[:n], src)
	}
}

func (r *responder) isOwn(src net.Addr) bool {
	host, _, err := net.SplitHostPort(src.String())
	if err != nil {
		return false
	}
	return r.net.isOwnAddr(host)
}

func (r *responder) handle(pkt []byte, src net.Addr) {
	var p dnsmessage.Parser
	hdr, err := p.Start(pkt)
	if err != nil {
		return
	}
	if hdr.Response {
		r.learnPeers(&p)
		return
	}
	r.answerQuestions(&p, src)
}

func (r *responder) answerQuestions(p *dnsmessage.Parser, src net.Addr) {
	for {
		q, err := p.Question()
		if err != nil {
			return
		}
		switch q.Name.String() {
		case mdnsService, r.instance, r.target:
			// Legacy queries use an ephemeral source port and require a unicast
			// response.
			if legacy, ok := legacySource(src); ok {
				if r.allowLegacy() {
					r.sendTo(r.buildRecords(mdnsTTL), legacy)
				}
				return
			}
			r.scheduleAnswer()
			return
		}
	}
}

func (r *responder) allowLegacy() bool {
	r.legacyMu.Lock()
	defer r.legacyMu.Unlock()
	return r.legacyBucket.take(time.Now(), legacyBurst, legacyPerSecond)
}

func legacySource(src net.Addr) (*net.UDPAddr, bool) {
	udp, ok := src.(*net.UDPAddr)
	if !ok || udp.Port == mdnsPort {
		return nil, false
	}
	return udp, true
}

// learnPeers extracts candidate addresses from SRV, TXT and A records. The
// resulting identity is still authenticated by PAKE.
func (r *responder) learnPeers(p *dnsmessage.Parser) {
	if err := p.SkipAllQuestions(); err != nil {
		return
	}
	var rrs []dnsmessage.Resource
	for _, section := range []func() ([]dnsmessage.Resource, error){
		p.AllAnswers, p.AllAuthorities, p.AllAdditionals,
	} {
		got, err := section()
		if err != nil {
			break
		}
		rrs = append(rrs, got...)
	}

	found, addrs := collectInstances(rrs)

	// Strip the monotonic component so time spent asleep counts toward peer age.
	now := time.Now().Round(0)
	for id, e := range found {
		if id == r.hostID || e.port == 0 {
			continue
		}
		if e.leaving {
			r.peers.drop(id)
			continue
		}
		if e.version != "" && e.version != txtVersion {
			continue
		}
		ip := addrs[e.target]
		if ip == nil {
			continue
		}
		r.peers.put(peer{
			HostID:   id,
			Hostname: e.hostname,
			Addr:     net.JoinHostPort(ip.String(), strconv.Itoa(int(e.port))),
			LastSeen: now,
		})
	}
}

// instance accumulates records for one advertised service.
type instance struct {
	port     uint16
	target   string
	hostname string
	version  string
	// A zero TTL is a goodbye and removes the peer immediately.
	leaving bool
}

// collectInstances groups service records and indexes addresses by SRV target.
func collectInstances(rrs []dnsmessage.Resource) (map[string]*instance, map[string]net.IP) {
	found := make(map[string]*instance)
	addrs := make(map[string]net.IP)

	// Ignore records belonging to other services.
	entry := func(name string) *instance {
		id, ok := strings.CutSuffix(name, "."+mdnsService)
		if !ok || id == "" {
			return nil
		}
		if found[id] == nil {
			found[id] = &instance{}
		}
		return found[id]
	}

	for _, rr := range rrs {
		name := rr.Header.Name.String()
		switch body := rr.Body.(type) {
		case *dnsmessage.SRVResource:
			if e := entry(name); e != nil {
				e.port, e.target = body.Port, body.Target.String()
				e.leaving = rr.Header.TTL == 0
			}
		case *dnsmessage.TXTResource:
			if e := entry(name); e != nil {
				readTXT(e, body.TXT)
			}
		case *dnsmessage.AResource:
			addrs[name] = net.IP(body.A[:])
		}
	}
	return found, addrs
}

func readTXT(e *instance, txt []string) {
	for _, kv := range txt {
		if v, ok := strings.CutPrefix(kv, "host="); ok {
			e.hostname = v
		}
		if v, ok := strings.CutPrefix(kv, "v="); ok {
			e.version = v
		}
	}
}

// scheduleAnswer coalesces queries behind a delayed reply and enforces a
// one second minimum between answers.
func (r *responder) scheduleAnswer() {
	r.answerMu.Lock()
	defer r.answerMu.Unlock()
	if r.answerPending {
		return
	}
	wait := answerDelayFloor + time.Duration(randIndex(int(answerDelayCeiling-answerDelayFloor)))
	if since := time.Since(r.lastAnswer); since < answerMinGap {
		wait = max(wait, answerMinGap-since)
	}
	r.answerPending = true
	time.AfterFunc(wait, func() {
		r.answerMu.Lock()
		r.answerPending = false
		r.lastAnswer = time.Now()
		r.answerMu.Unlock()
		r.send(r.buildRecords(mdnsTTL))
	})
}

// buildRecords creates this machine's PTR, SRV, TXT and address records. A zero
// TTL turns the announcement into a goodbye.
func (r *responder) buildRecords(ttl uint32) []byte {
	header := func(name string, t dnsmessage.Type, class dnsmessage.Class) dnsmessage.ResourceHeader {
		return dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName(name),
			Type:  t,
			Class: class,
			TTL:   ttl,
		}
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{Response: true, Authoritative: true},
		Answers: []dnsmessage.Resource{
			{
				// The service PTR is shared by every host and must not flush peers.
				Header: header(mdnsService, dnsmessage.TypePTR, dnsmessage.ClassINET),
				Body:   &dnsmessage.PTRResource{PTR: dnsmessage.MustNewName(r.instance)},
			},
			{
				Header: header(r.instance, dnsmessage.TypeSRV, classFlush),
				Body: &dnsmessage.SRVResource{
					Port:   uint16(r.port), //nolint:gosec // A TCP port always fits.
					Target: dnsmessage.MustNewName(r.target),
				},
			},
			{
				Header: header(r.instance, dnsmessage.TypeTXT, classFlush),
				Body:   &dnsmessage.TXTResource{TXT: []string{"v=" + txtVersion, "host=" + r.hostname}},
			},
		},
	}
	for _, ifi := range r.net.interfaces() {
		ip := ip4(ifi)
		if ip == nil {
			continue
		}
		msg.Answers = append(msg.Answers, dnsmessage.Resource{
			Header: header(r.target, dnsmessage.TypeA, classFlush),
			Body:   &dnsmessage.AResource{A: [4]byte(ip)},
		})
	}
	buf, err := msg.Pack()
	if err != nil {
		return nil
	}
	return buf
}

func (r *responder) send(buf []byte) {
	if buf == nil {
		return
	}
	if r.onSend != nil {
		r.onSend(buf)
		return
	}
	r.sendMu.Lock()
	defer r.sendMu.Unlock()
	dst := &net.UDPAddr{IP: mdnsGroup, Port: mdnsPort}
	for _, ifi := range r.net.interfaces() {
		if err := r.conn.SetMulticastInterface(&ifi); err != nil {
			continue
		}
		_, _ = r.conn.WriteTo(buf, nil, dst)
	}
}

func (r *responder) sendTo(buf []byte, dst *net.UDPAddr) {
	if buf == nil {
		return
	}
	if r.onSend != nil {
		r.onSend(buf)
		return
	}
	r.sendMu.Lock()
	defer r.sendMu.Unlock()
	_, _ = r.conn.WriteTo(buf, nil, dst)
}
