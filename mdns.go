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

// Service type _tp._tcp.local, one instance per machine and never one per paste.
// Discovery only turns a host ID into a candidate address. A spoofed answer
// leads to a PAKE that fails key confirmation, so mDNS is a hint and never an
// authority.
//
// Discovery is announcement driven rather than query driven. Announcing on a
// timer costs one packet per machine per interval, which grows with the size of
// the network. Everyone answering everyone's queries grows with its square: a
// thousand machines asking every thirty seconds is thirty thousand packets a
// second, and wifi carries multicast at its slowest rate.
const (
	mdnsService = "_tp._tcp.local."
	mdnsPort    = 5353

	announceInterval = 10 * time.Minute
	peerLifetime     = 25 * time.Minute
	mdnsTTL          = uint32(peerLifetime / time.Second)
	browseWhenEmpty  = time.Minute

	// Without a delay, one query puts a reply from every machine on the air in
	// the same millisecond.
	answerDelayFloor   = 20 * time.Millisecond
	answerDelayCeiling = 120 * time.Millisecond
	answerMinGap       = time.Second

	legacyBurst     = 5
	legacyPerSecond = 5

	quietPeriod = 15 * time.Second
)

// startupBurst is when the first announcements and query go out. Repeating them
// covers a dropped packet without waiting for announceInterval.
var startupBurst = []time.Duration{0, time.Second, 3 * time.Second}

var mdnsGroup = net.IPv4(224, 0, 0, 251)

// classFlush is ClassINET with the RFC 6762 cache flush bit, which applies to
// records unique to one machine, meaning everything here except the shared
// service PTR. Without it, other Bonjour caches keep a stale address after this
// machine changes network.
const classFlush = dnsmessage.ClassINET | 0x8000

type peer struct {
	HostID   string    `json:"host_id"`
	Hostname string    `json:"hostname"`
	Addr     string    `json:"addr"`
	LastSeen time.Time `json:"last_seen"`
}

// txtVersion is advertised so peers on an unsupported version are skipped rather
// than dialled and failed. A network holds both versions during a rollout.
const txtVersion = "1"

type peerTable struct {
	mu sync.Mutex
	m  map[string]peer

	// packets counts inbound mDNS datagrams from other machines, and anyPackets
	// counts every one including this machine's own.
	//
	// The diagnostic uses anyPackets, because a home network whose only mDNS
	// speaker is this Mac is silent by nature: mDNSResponder answering our own
	// query arrives from our own address, and counting only other machines makes
	// a working socket look blocked. A socket that cannot receive multicast at
	// all sees nothing, not even that.
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

// diagnostic returns empty unless multicast is provably not arriving, which
// otherwise reads as a bug in tp.
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

// listenMDNS binds port 5353 alongside mDNSResponder on macOS and Avahi on
// Linux, which already hold it. SO_REUSEADDR and SO_REUSEPORT must both be set
// before the group join or the bind fails.
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
	daemon *daemon
	conn   *ipv4.PacketConn

	// instance is <hostID>._tp._tcp.local. and target is <hostID>.local.
	instance string
	target   string
	hostname string

	// joined tracks which interfaces the group has been joined on, keyed by
	// name, so a refresh can tell what is new.
	joinedMu sync.Mutex
	joined   map[string]bool

	// SetMulticastInterface is per socket state, so sends must not overlap.
	sendMu sync.Mutex

	answerMu      sync.Mutex
	answerPending bool
	lastAnswer    time.Time

	// legacyMu guards a token bucket for unicast replies. They go to whatever
	// address the query claimed, UDP sources are forgeable, and the reply is
	// larger than the question, which without a ceiling is a reflector.
	legacyMu     sync.Mutex
	legacyBucket bucket

	// onSend replaces the socket write in tests.
	onSend func([]byte)
}

// startMDNS returns a stop function that sends a goodbye and closes the socket.
// It must run synchronously before the socket closes, or the goodbye never
// leaves.
func startMDNS(ctx context.Context, d *daemon) (func(), error) {
	noop := func() {}
	conn, err := listenMDNS(ctx)
	if err != nil {
		return noop, err
	}
	if err := conn.SetMulticastLoopback(true); err != nil {
		_ = conn.Close()
		return noop, err
	}

	name, _ := os.Hostname()
	r := &responder{
		daemon:   d,
		conn:     conn,
		joined:   make(map[string]bool),
		instance: d.hostID + "." + mdnsService,
		target:   d.hostID + ".local.",
		hostname: strings.TrimSuffix(name, ".local"),
	}
	// Joining fails when no interface is usable yet, which is normal on a
	// machine that booted with its wifi off. netLoop calls networkChanged once
	// one appears.
	_ = r.syncGroups()
	d.onNetChange = r.networkChanged
	d.probe = r.query

	go r.readLoop()
	go r.announceLoop(ctx)
	go r.browseLoop(ctx)

	return func() {
		// A goodbye drops this address from peer caches immediately, instead of
		// leaving fetches to spend a dial timeout on it for peerLifetime.
		r.send(r.buildRecords(0))
		_ = conn.Close()
	}, nil
}

// syncGroups joins the multicast group on newly appeared interfaces and forgets
// departed ones. No explicit leave is needed, since a vanished interface takes
// its membership with it.
func (r *responder) syncGroups() error {
	ifaces := r.daemon.net.interfaces()

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

// networkChanged runs from netLoop after the usable interfaces change. The peer
// table has already been cleared by then.
func (r *responder) networkChanged() {
	if err := r.syncGroups(); err != nil {
		return
	}
	r.send(r.buildRecords(mdnsTTL))
	r.query()
}

// jitter spreads an interval over plus or minus a quarter, so machines that
// booted together do not stay in lockstep.
func jitter(d time.Duration) time.Duration {
	return d*3/4 + time.Duration(randIndex(int(d/2)))
}

// announceLoop carries discovery in steady state at one packet per interval.
func (r *responder) announceLoop(ctx context.Context) {
	for _, delay := range startupBurst {
		if !sleep(ctx, delay) {
			return
		}
		r.send(r.buildRecords(mdnsTTL))
	}
	for sleep(ctx, jitter(announceInterval)) {
		r.send(r.buildRecords(mdnsTTL))
	}
}

// browseLoop queries at startup and after that only while the peer table is
// empty, which is self limiting: a busy network never asks, and an empty one has
// nobody to answer.
func (r *responder) browseLoop(ctx context.Context) {
	for _, delay := range startupBurst {
		if !sleep(ctx, delay) {
			return
		}
		r.query()
	}
	for sleep(ctx, browseWhenEmpty) {
		if len(r.daemon.peers.list()) == 0 {
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
		r.daemon.peers.anyPackets.Add(1)
		if !r.isOwn(src) {
			r.daemon.peers.packets.Add(1)
		}
		r.handle(buf[:n], src)
	}
}

func (r *responder) isOwn(src net.Addr) bool {
	host, _, err := net.SplitHostPort(src.String())
	if err != nil {
		return false
	}
	return r.daemon.net.isOwnAddr(host)
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
			// A source port other than 5353 is a one shot legacy query whose
			// sender is not on the group, so only a unicast reply reaches it.
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

// learnPeers reads SRV, TXT and A records out of a response. Nothing here is
// trusted beyond "try this address".
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

	// Round(0) strips the monotonic reading so peer ages use the wall clock. The
	// monotonic clock stops while a laptop is asleep, which would leave the
	// table looking fresh on a network it has never seen.
	now := time.Now().Round(0)
	for id, e := range found {
		if id == r.daemon.hostID || e.port == 0 {
			continue
		}
		if e.leaving {
			r.daemon.peers.drop(id)
			continue
		}
		if e.version != "" && e.version != txtVersion {
			continue
		}
		ip := addrs[e.target]
		if ip == nil {
			continue
		}
		r.daemon.peers.put(peer{
			HostID:   id,
			Hostname: e.hostname,
			Addr:     net.JoinHostPort(ip.String(), strconv.Itoa(int(e.port))),
			LastSeen: now,
		})
	}
}

// instance is one advertised service, assembled from records that may arrive in
// any section of a response.
type instance struct {
	port     uint16
	target   string
	hostname string
	version  string
	// leaving is set by a TTL of zero, which is a goodbye. The address is
	// dropped now instead of leaving fetches to time out on it for peerLifetime.
	leaving bool
}

// collectInstances groups records by service instance and collects the A
// records their SRV targets point at.
func collectInstances(rrs []dnsmessage.Resource) (map[string]*instance, map[string]net.IP) {
	found := make(map[string]*instance)
	addrs := make(map[string]net.IP)

	// entry returns the accumulator for an instance of this service, or nil for
	// records belonging to any other service on the LAN.
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

// scheduleAnswer replies after a random delay, folding every query arriving in
// the meantime into that one reply and never answering more than once a
// second.
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

// buildRecords builds this machine's announcement: one PTR, one SRV, one TXT and
// one A per advertised address. A ttl of zero makes it a goodbye.
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
				// Shared record, so no cache flush bit. Every machine has a PTR
				// under this same name.
				Header: header(mdnsService, dnsmessage.TypePTR, dnsmessage.ClassINET),
				Body:   &dnsmessage.PTRResource{PTR: dnsmessage.MustNewName(r.instance)},
			},
			{
				Header: header(r.instance, dnsmessage.TypeSRV, classFlush),
				Body: &dnsmessage.SRVResource{
					Port:   uint16(r.daemon.port), //nolint:gosec // A TCP port always fits.
					Target: dnsmessage.MustNewName(r.target),
				},
			},
			{
				Header: header(r.instance, dnsmessage.TypeTXT, classFlush),
				Body:   &dnsmessage.TXTResource{TXT: []string{"v=" + txtVersion, "host=" + r.hostname}},
			},
		},
	}
	for _, ifi := range r.daemon.net.interfaces() {
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
	for _, ifi := range r.daemon.net.interfaces() {
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
