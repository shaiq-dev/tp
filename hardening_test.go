package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"math"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Per IP limits do not bound guessing on a LAN, where an attacker assigns itself
// as many addresses as the subnet holds.
func TestGlobalRateLimit(t *testing.T) {
	l := newLimiter()
	allowed := 0
	for i := range globalBurst * 4 {
		// A different source every time, which is all it takes to defeat a per
		// IP bucket.
		if l.allowPeer("10.0.0."+strconv.Itoa(i%256)) && l.allowExchange() {
			allowed++
		}
	}
	if allowed != globalBurst {
		t.Errorf("%d exchanges got through, want the global burst of %d", allowed, globalBurst)
	}
}

// Charging the global bucket at accept let a bare TCP flood, which tests no
// password at all, deny service to everyone.
func TestCheapFloodDoesNotDrainTheSharedBudget(t *testing.T) {
	l := newLimiter()
	for i := range 10 * globalBurst {
		// Connections that never reach the offer.
		l.allowPeer("10.0.0." + strconv.Itoa(i%256))
	}
	allowed := 0
	for range globalBurst {
		if l.allowExchange() {
			allowed++
		}
	}
	if allowed != globalBurst {
		t.Errorf("%d real exchanges left after a connect flood, want %d", allowed, globalBurst)
	}
}

func TestPerIPLimitStillApplies(t *testing.T) {
	l := newLimiter()
	allowed := 0
	for range rateBurst * 2 {
		if l.allowPeer("10.0.0.1") {
			allowed++
		}
	}
	if allowed != rateBurst {
		t.Errorf("one source got %d exchanges, want %d", allowed, rateBurst)
	}
	if !l.allowPeer("10.0.0.2") {
		t.Error("a second source was refused")
	}
}

// An attacker using a fresh source address per attempt, so only the global
// bucket applies. Without it a daemon served 3508 guesses a second, which walks
// the 2^31 keyspace in days.
func TestGuessRateIsGloballyBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("hammers a daemon for a few seconds")
	}
	d, addr := newTestDaemon(t)
	addTestPaste(t, d, "acid-acorn-acre", "secret")

	rotate := t.Context()
	go func() {
		for rotate.Err() == nil {
			time.Sleep(5 * time.Millisecond)
			d.limiter.mu.Lock()
			clear(d.limiter.ip) // stands in for rotating source addresses
			d.limiter.mu.Unlock()
		}
	}()

	wrong, err := derivePRS("acid-acorn-adobe")
	if err != nil {
		t.Fatal(err)
	}

	var served atomic.Int64
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for ctx.Err() == nil {
				if oracleReached(ctx, addr, wrong) {
					served.Add(1)
				}
			}
		})
	}
	start := time.Now()
	wg.Wait()
	elapsed := time.Since(start)

	// The burst is spent once, leaving the sustained rate.
	allowed := float64(globalBurst) + globalPerSecond*elapsed.Seconds()
	got := float64(served.Load())
	t.Logf("%.0f guesses served in %v, ceiling %.0f", got, elapsed.Round(time.Millisecond), allowed)
	t.Logf("sustained %d/s puts 2^31 codes at about %.1f years for an even chance",
		globalPerSecond, math.Pow(2, 31)/2/globalPerSecond/(365*24*3600))
	if got > allowed*1.2 {
		t.Errorf("the global cap is not holding: %.0f served, ceiling %.0f", got, allowed)
	}
}

// oracleReached reports whether the daemon produced an offer, which is what
// makes one connection worth one password guess.
func oracleReached(ctx context.Context, addr string, prs []byte) bool {
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer raw.Close()
	conn := tls.Client(raw, &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		NextProtos:         []string{alpnProto},
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		return false
	}
	conn.SetDeadline(time.Now().Add(pakeTimeout))
	sid, err := channelBinding(conn)
	if err != nil {
		return false
	}
	leaf := conn.ConnectionState().PeerCertificates[0]
	side := newPakeSide(prs, channelID(hostID(leaf.RawSubjectPublicKeyInfo)), sid)
	if err := writeFrame(conn, append([]byte{wireVersion}, side.share...)); err != nil {
		return false
	}
	_, err = readFrame(conn, maxOfferLen)
	return err == nil
}

func TestSealedPayload(t *testing.T) {
	sid, ci := make([]byte, 32), channelID("HOST12345678")
	prs := randomPRS(t)
	server, client := newPakeSide(prs, ci, sid), newPakeSide(prs, ci, sid)
	if err := server.finish(client.share, sid); err != nil {
		t.Fatal(err)
	}
	if err := client.finish(server.share, sid); err != nil {
		t.Fatal(err)
	}

	body := []byte("a paste that TLS alone should not be the only thing protecting")
	sealed, err := server.seal(body)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, body) {
		t.Fatal("the payload went out in the clear")
	}
	got, err := client.open(sealed)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("open = %q, %v", got, err)
	}

	tampered := bytes.Clone(sealed)
	tampered[0] ^= 0xff
	if _, err := client.open(tampered); err == nil {
		t.Error("a tampered payload was accepted")
	}

	stranger := newPakeSide(randomPRS(t), ci, sid)
	if err := stranger.finish(server.share, sid); err != nil {
		t.Fatal(err)
	}
	if _, err := stranger.open(sealed); err == nil {
		t.Error("the wrong password opened the payload")
	}
}

// A peer that cannot name the protocol is turned away in the TLS handshake
// rather than partway through an exchange.
func TestALPNRequired(t *testing.T) {
	_, addr := newTestDaemon(t)
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	conn := tls.Client(raw, &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true})
	if err := conn.HandshakeContext(t.Context()); err != nil {
		return // rejected outright, which is fine
	}
	conn.SetDeadline(time.Now().Add(pakeTimeout))
	if err := writeFrame(conn, make([]byte, helloLen)); err != nil {
		return
	}
	if _, err := readFrame(conn, maxOfferLen); err == nil {
		t.Error("the daemon answered a peer that did not negotiate the protocol")
	}
}

// Regression for a cold tp get. A daemon forked by the calling command has an
// empty peer table for a few hundred milliseconds, and a fetch that does not
// wait it out reports an empty network.
func TestColdGetWaitsForDiscovery(t *testing.T) {
	d, _ := newTestDaemon(t)
	srv := newControlServer(t, d)

	probed := make(chan struct{}, 1)
	d.probe = func() {
		select {
		case probed <- struct{}{}:
		default:
		}
		// Stands in for an announcement arriving a moment after the query.
		time.AfterFunc(50*time.Millisecond, func() {
			d.peers.put(peer{HostID: "PEER12345678", Addr: "10.0.0.7:7391", LastSeen: time.Now()})
		})
	}

	var out struct {
		Peers []peer `json:"peers"`
	}
	start := time.Now()
	if err := srv.do(t.Context(), "GET", "/peers?wait=2s", "", &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Peers) == 0 {
		t.Fatal("a cold fetch gave up before discovery had answered")
	}
	select {
	case <-probed:
	default:
		t.Error("an empty table should provoke a query rather than just waiting")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("waited %v after the peer arrived, want to return promptly", elapsed)
	}
}

// The other side of the cold start fix. A settled daemon with no peers must not
// spend discoveryWait on every fetch.
func TestNoWaitOnALonelyNetwork(t *testing.T) {
	d, _ := newTestDaemon(t)
	d.started = time.Now().Add(-2 * peerWarmup)
	srv := newControlServer(t, d)
	d.probe = func() { t.Error("a settled daemon should not keep asking on every fetch") }

	start := time.Now()
	if err := srv.do(t.Context(), "GET", "/peers?wait=2s", "", nil); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Errorf("a lonely fetch waited %v", elapsed)
	}
}

func TestPeersReturnsImmediatelyWhenWarm(t *testing.T) {
	d, _ := newTestDaemon(t)
	srv := newControlServer(t, d)
	d.peers.put(peer{HostID: "PEER12345678", Addr: "10.0.0.7:7391", LastSeen: time.Now()})
	d.probe = func() { t.Error("a warm table should not provoke a query") }

	start := time.Now()
	if err := srv.do(t.Context(), "GET", "/peers?wait=5s", "", nil); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("waited %v with a warm table", elapsed)
	}
}

// Unicast answers go to whatever address the query claimed, and UDP sources are
// forgeable, so an uncapped reply path is a reflector.
func TestLegacyRepliesAreCapped(t *testing.T) {
	var sent int
	r := &responder{
		daemon:   &daemon{peers: newPeerTable(), net: emptyNetFilter(), hostID: "SELF12345678"},
		instance: "SELF12345678." + mdnsService,
		target:   "SELF12345678.local.",
		onSend:   func([]byte) { sent++ },
	}
	for range 100 {
		if r.allowLegacy() {
			r.sendTo(r.buildRecords(mdnsTTL), nil)
		}
	}
	if sent != legacyBurst {
		t.Errorf("answered %d one shot queries in a burst, want %d", sent, legacyBurst)
	}
}

// A machine that booted with its wifi off has no interface to join. Discovery
// has to stay startable so netLoop can pick it up later.
func TestMDNSStartsWithoutInterfaces(t *testing.T) {
	f := &netFilter{addrs: map[string]bool{}}
	r := &responder{
		daemon:   &daemon{peers: newPeerTable(), net: f, hostID: "SELF12345678"},
		joined:   map[string]bool{},
		instance: "SELF12345678." + mdnsService,
		target:   "SELF12345678.local.",
	}
	if err := r.syncGroups(); !errors.Is(err, errNoInterface) {
		t.Fatalf("syncGroups with no interfaces returned %v", err)
	}
	// An announcement still builds, ready for the moment one appears.
	if len(r.buildRecords(mdnsTTL)) == 0 {
		t.Error("no announcement could be built")
	}
}

func TestIsLoopback(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:7391", true},
		{"[::1]:7391", true},
		{"192.168.1.55:7391", false},
		{"nonsense", false},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			if got := isLoopback(tt.addr); got != tt.want {
				t.Errorf("isLoopback(%q) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

func TestNetFilterServes(t *testing.T) {
	f := &netFilter{addrs: map[string]bool{"192.168.1.55": true}}
	tests := []struct {
		name  string
		local string
		want  bool
	}{
		{"an advertised address", "192.168.1.55:7391", true},
		{"loopback for our own fetches", "127.0.0.1:7391", true},
		{"an address on an excluded interface", "10.8.0.2:7391", false},
		{"nonsense", "not-an-address", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := f.serves(fakeAddr(tt.local)); got != tt.want {
				t.Errorf("serves(%s) = %v, want %v", tt.local, got, tt.want)
			}
		})
	}
}

type fakeAddr string

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return string(a) }

func TestRetryableAccept(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"out of descriptors", syscall.EMFILE, true},
		{"system wide descriptor limit", syscall.ENFILE, true},
		{"out of buffers", syscall.ENOBUFS, true},
		{"listener closed", net.ErrClosed, false},
		{"connection refused", syscall.ECONNREFUSED, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := retryableAccept(tt.err); got != tt.want {
				t.Errorf("retryableAccept(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestIdleDaemonStops(t *testing.T) {
	d := &daemon{store: newStore()}
	tests := []struct {
		name  string
		setup func()
		want  bool
	}{
		{"busy and empty", func() { d.touch() }, false},
		{"idle and empty", func() { d.lastUsed.Store(time.Now().Add(-2 * idleTimeout).Unix()) }, true},
		{"idle but holding a paste", func() {
			d.store.add(&paste{ExpiresAt: time.Now().Add(time.Hour), prs: randomPRS(t), data: []byte("x")})
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()
			if got := d.shouldStop(); got != tt.want {
				t.Errorf("shouldStop() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPeerVersionFiltering(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    int
	}{
		{"our version", txtVersion, 1},
		{"a version we cannot speak", "2", 0},
		{"no version at all", "", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			self := &daemon{peers: newPeerTable(), net: emptyNetFilter(), hostID: "SELF12345678"}
			r := &responder{daemon: self}

			txt := []string{"host=theirs"}
			if tt.version != "" {
				txt = append(txt, "v="+tt.version)
			}
			pkt := withARecord(t, peerAnnouncement(t, "PEER12345678", 4242, txt), "PEER12345678.local.", net.IPv4(10, 0, 0, 7))

			var p dnsmessage.Parser
			if _, err := p.Start(pkt); err != nil {
				t.Fatal(err)
			}
			r.learnPeers(&p)
			if got := len(self.peers.list()); got != tt.want {
				t.Errorf("learned %d peers, want %d", got, tt.want)
			}
		})
	}
}

// RFC 6762 puts the cache flush bit on records unique to one machine and not on
// shared ones, which here means everything except the service PTR.
func TestCacheFlushBit(t *testing.T) {
	r := &responder{
		daemon:   &daemon{peers: newPeerTable(), net: emptyNetFilter(), hostID: "SELF12345678", port: 7391},
		instance: "SELF12345678." + mdnsService,
		target:   "SELF12345678.local.",
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(r.buildRecords(mdnsTTL)); err != nil {
		t.Fatal(err)
	}
	for _, rr := range msg.Answers {
		flush := rr.Header.Class&0x8000 != 0
		want := rr.Header.Type != dnsmessage.TypePTR
		if flush != want {
			t.Errorf("%s %v: cache flush bit %v, want %v", rr.Header.Name, rr.Header.Type, flush, want)
		}
	}
}

func TestLegacySource(t *testing.T) {
	tests := []struct {
		name string
		addr *net.UDPAddr
		want bool
	}{
		{"a normal responder", &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: mdnsPort}, false},
		{"a one shot query", &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 51234}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, got := legacySource(tt.addr); got != tt.want {
				t.Errorf("legacySource = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKnownHostsCompaction(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	for i := range 20 {
		if err := savePin("HOST1", pin{SPKI: "key" + strconv.Itoa(i), Hostname: "laptop"}); err != nil {
			t.Fatal(err)
		}
	}
	pins, lines := readPins()
	if len(pins) != 1 {
		t.Fatalf("%d entries, want 1", len(pins))
	}
	if lines > 4 {
		t.Errorf("known_hosts holds %d lines for 1 entry, compaction is not running", lines)
	}
	if got := pins["HOST1"].SPKI; got != "key19" {
		t.Errorf("newest pin is %q, want key19", got)
	}
}

func peerAnnouncement(t *testing.T, hostID string, port uint16, txt []string) []byte {
	t.Helper()
	instance := hostID + "." + mdnsService
	header := func(name string, typ dnsmessage.Type) dnsmessage.ResourceHeader {
		return dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName(name),
			Type:  typ,
			Class: dnsmessage.ClassINET,
			TTL:   mdnsTTL,
		}
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{Response: true, Authoritative: true},
		Answers: []dnsmessage.Resource{
			{
				Header: header(instance, dnsmessage.TypeSRV),
				Body: &dnsmessage.SRVResource{
					Port:   port,
					Target: dnsmessage.MustNewName(hostID + ".local."),
				},
			},
			{Header: header(instance, dnsmessage.TypeTXT), Body: &dnsmessage.TXTResource{TXT: txt}},
		},
	}
	pkt, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return pkt
}
