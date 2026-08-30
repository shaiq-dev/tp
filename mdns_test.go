package main

import (
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// emptyNetFilter leaves a responder with no interfaces, so buildRecords emits no
// A record and a test can supply its own.
func emptyNetFilter() *netFilter {
	return &netFilter{addrs: map[string]bool{}}
}

func TestExcluded(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"en0", false},
		{"eth0", false},
		{"wlan0", false},
		{"enp3s0", false},
		{"docker0", true},
		{"br-abc123", true},
		{"veth1a2b", true},
		{"vboxnet0", true},
		{"tun0", true},
		{"utun4", true},
		{"wg0", true},
		{"awdl0", true},
		{"llw0", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := excluded(tt.name); got != tt.want {
				t.Errorf("excluded(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestPeerTableSweep(t *testing.T) {
	tbl := newPeerTable()
	tbl.put(peer{HostID: "FRESH", LastSeen: time.Now()})
	tbl.put(peer{HostID: "STALE", LastSeen: time.Now().Add(-2 * peerLifetime)})

	tbl.sweep()
	got := tbl.list()
	if len(got) != 1 || got[0].HostID != "FRESH" {
		t.Errorf("after sweep the table holds %+v, want only FRESH", got)
	}
}

func TestPeerTableDiagnostic(t *testing.T) {
	tests := []struct {
		name    string
		started time.Time
		packets int64
		want    bool
	}{
		{"too early to judge", time.Now(), 0, false},
		{"traffic is arriving", time.Now().Add(-time.Minute), 1, false},
		{"silent network", time.Now().Add(-time.Minute), 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tbl := newPeerTable()
			tbl.started = tt.started
			tbl.packets.Store(tt.packets)
			if got := tbl.diagnostic() != ""; got != tt.want {
				t.Errorf("diagnostic present = %v, want %v", got, tt.want)
			}
		})
	}
}

// Feeds the parser a response shaped the way buildRecords emits one, which is
// the only shape that has to round trip.
func TestLearnPeers(t *testing.T) {
	self := &daemon{peers: newPeerTable(), net: emptyNetFilter(), hostID: "SELF12345678", port: 7391}
	r := &responder{
		daemon:   self,
		instance: "SELF12345678." + mdnsService,
		target:   "SELF12345678.local.",
		hostname: "mine",
	}

	other := &daemon{peers: newPeerTable(), net: emptyNetFilter(), hostID: "PEER12345678", port: 4242}
	sender := &responder{
		daemon:   other,
		instance: "PEER12345678." + mdnsService,
		target:   "PEER12345678.local.",
		hostname: "theirs",
	}
	pkt := sender.buildRecords(mdnsTTL)
	// buildRecords only emits A records for real interfaces, so this adds one.
	pkt = withARecord(t, pkt, sender.target, net.IPv4(10, 0, 0, 7))

	var p dnsmessage.Parser
	if _, err := p.Start(pkt); err != nil {
		t.Fatal(err)
	}
	r.learnPeers(&p)

	peers := self.peers.list()
	if len(peers) != 1 {
		t.Fatalf("learned %d peers, want 1", len(peers))
	}
	got := peers[0]
	if got.HostID != "PEER12345678" || got.Addr != "10.0.0.7:4242" || got.Hostname != "theirs" {
		t.Errorf("learned %+v", got)
	}
}

// A busy LAN carries mDNS for printers and speakers on the same group, none of
// which belong in the candidate list.
func TestLearnPeersIgnoresOtherServices(t *testing.T) {
	self := &daemon{peers: newPeerTable(), hostID: "SELF12345678"}
	r := &responder{daemon: self}

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{Response: true},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{
				Name:  dnsmessage.MustNewName("printer._ipp._tcp.local."),
				Type:  dnsmessage.TypeSRV,
				Class: dnsmessage.ClassINET,
			},
			Body: &dnsmessage.SRVResource{
				Port:   631,
				Target: dnsmessage.MustNewName("printer.local."),
			},
		}},
	}
	pkt, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	pkt = withARecord(t, pkt, "printer.local.", net.IPv4(10, 0, 0, 9))

	var p dnsmessage.Parser
	if _, err := p.Start(pkt); err != nil {
		t.Fatal(err)
	}
	r.learnPeers(&p)

	if got := self.peers.list(); len(got) != 0 {
		t.Errorf("learned %+v from another service", got)
	}
}

// withARecord appends an A record to a packed message, supplying an address
// without a real network interface.
func withARecord(t *testing.T, pkt []byte, name string, ip net.IP) []byte {
	t.Helper()
	var msg dnsmessage.Message
	if err := msg.Unpack(pkt); err != nil {
		t.Fatal(err)
	}
	ttl := mdnsTTL
	if len(msg.Answers) > 0 {
		ttl = msg.Answers[0].Header.TTL
	}
	msg.Answers = append(msg.Answers, dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName(name),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
			TTL:   ttl,
		},
		Body: &dnsmessage.AResource{A: [4]byte(ip.To4())},
	})
	out, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The flood defence. However many queries land, one machine puts out one
// reply.
func TestScheduleAnswerCoalesces(t *testing.T) {
	sent := make(chan struct{}, 100)
	r := &responder{
		daemon:   &daemon{peers: newPeerTable(), net: emptyNetFilter(), hostID: "SELF12345678"},
		instance: "SELF12345678." + mdnsService,
		target:   "SELF12345678.local.",
		onSend:   func([]byte) { sent <- struct{}{} },
	}
	for range 50 {
		r.scheduleAnswer()
	}
	select {
	case <-sent:
	case <-time.After(2 * answerDelayCeiling):
		t.Fatal("no reply was scheduled")
	}
	select {
	case <-sent:
		t.Fatal("50 queries produced more than one reply")
	case <-time.After(2 * answerDelayCeiling):
	}
}

// Sending a goodbye is only half of it. The receiving side has to act on the
// zero TTL, which it silently did not.
func TestGoodbyeDropsThePeer(t *testing.T) {
	self := &daemon{peers: newPeerTable(), hostID: "SELF12345678"}
	r := &responder{daemon: self}
	leaver := &responder{
		daemon:   &daemon{peers: newPeerTable(), net: emptyNetFilter(), hostID: "PEER12345678", port: 4242},
		instance: "PEER12345678." + mdnsService,
		target:   "PEER12345678.local.",
		hostname: "theirs",
	}

	for _, step := range []struct {
		name string
		ttl  uint32
		want int
	}{
		{"announcement adds the peer", mdnsTTL, 1},
		{"goodbye removes it", 0, 0},
	} {
		t.Run(step.name, func(t *testing.T) {
			pkt := withARecord(t, leaver.buildRecords(step.ttl), leaver.target, net.IPv4(10, 0, 0, 7))
			var p dnsmessage.Parser
			if _, err := p.Start(pkt); err != nil {
				t.Fatal(err)
			}
			r.learnPeers(&p)
			if got := len(self.peers.list()); got != step.want {
				t.Errorf("peer table holds %d, want %d", got, step.want)
			}
		})
	}
}

func TestGoodbyeRecordsHaveZeroTTL(t *testing.T) {
	r := &responder{
		daemon:   &daemon{peers: newPeerTable(), net: emptyNetFilter(), hostID: "SELF12345678", port: 7391},
		instance: "SELF12345678." + mdnsService,
		target:   "SELF12345678.local.",
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(r.buildRecords(0)); err != nil {
		t.Fatal(err)
	}
	for _, rr := range msg.Answers {
		if rr.Header.TTL != 0 {
			t.Errorf("%s has TTL %d, want 0", rr.Header.Name, rr.Header.TTL)
		}
	}
}

func TestJitterStaysInRange(t *testing.T) {
	const d = time.Minute
	for range 200 {
		got := jitter(d)
		if got < d*3/4 || got >= d*5/4 {
			t.Fatalf("jitter(%v) = %v, outside the expected quarter either side", d, got)
		}
	}
}

func TestCompletionScriptsCoverEveryCommand(t *testing.T) {
	scripts := map[string]string{
		"bash": bashCompletion,
		"zsh":  zshCompletion,
		"fish": fishCompletion,
	}
	for shell, script := range scripts {
		t.Run(shell, func(t *testing.T) {
			for _, cmd := range []string{"post", "get", "list", "del", "completion"} {
				if !strings.Contains(script, cmd) {
					t.Errorf("%s completion is missing %q", shell, cmd)
				}
			}
		})
	}
}
