package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"
)

// newTestDaemon brings up a real TLS listener, so the handshake runs against a
// genuine channel binding rather than a stub.
func newTestDaemon(t *testing.T) (*daemon, string) {
	t.Helper()
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	return newTestDaemonRaw(t)
}

func newTestDaemonRaw(tb testing.TB) (*daemon, string) {
	tb.Helper()
	cert, err := loadIdentity()
	if err != nil {
		tb.Fatal(err)
	}
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{alpnProto},
	})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = l.Close() })

	d := &daemon{
		store:   newStore(),
		limiter: newLimiter(),
		peers:   newPeerTable(),
		net:     newNetFilter(),
		hostID:  hostID(cert.Leaf.RawSubjectPublicKeyInfo),
		port:    l.Addr().(*net.TCPAddr).Port,
		started: time.Now(),
	}
	go func() { _ = d.serveData(tb.Context(), l) }()
	return d, l.Addr().String()
}

func addTestPaste(t *testing.T, d *daemon, code, body string, opts ...func(*paste)) []byte {
	t.Helper()
	prs, err := derivePRS(code)
	if err != nil {
		t.Fatal(err)
	}
	p := testPaste("", body, opts...)
	p.prs = prs
	if err := d.store.add(p); err != nil {
		t.Fatal(err)
	}
	return prs
}

func TestHandshake(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T, d *daemon) (prs []byte)
		wantBody string
		wantErr  error
	}{
		{
			name: "the holder serves the paste",
			setup: func(t *testing.T, d *daemon) []byte {
				t.Helper()
				addTestPaste(t, d, "blaze-cobra-drift", "a second paste")
				return addTestPaste(t, d, "acid-acorn-acre", "hello from tp")
			},
			wantBody: "hello from tp",
		},
		{
			name: "a burn paste delivers its payload once",
			setup: func(t *testing.T, d *daemon) []byte {
				t.Helper()
				return addTestPaste(t, d, "acid-acorn-acre", "topsecret", maxGets(1))
			},
			wantBody: "topsecret",
		},
		{
			name: "a wrong code matches nothing",
			setup: func(t *testing.T, d *daemon) []byte {
				t.Helper()
				addTestPaste(t, d, "acid-acorn-acre", "hello")
				prs, err := derivePRS("acid-acorn-adobe")
				if err != nil {
					t.Fatal(err)
				}
				return prs
			},
			wantErr: errNoMatch,
		},
		{
			name: "a host holding nothing still answers",
			setup: func(t *testing.T, _ *daemon) []byte {
				t.Helper()
				prs, err := derivePRS("acid-acorn-acre")
				if err != nil {
					t.Fatal(err)
				}
				return prs
			},
			wantErr: errNoMatch,
		},
		{
			name: "a burned paste is indistinguishable from an absent one",
			setup: func(t *testing.T, d *daemon) []byte {
				t.Helper()
				prs := addTestPaste(t, d, "acid-acorn-acre", "gone", maxGets(1))
				d.store.take(prs)
				return prs
			},
			wantErr: errNoMatch,
		},
		{
			name: "an expired paste is not served",
			setup: func(t *testing.T, d *daemon) []byte {
				t.Helper()
				return addTestPaste(t, d, "acid-acorn-acre", "stale", expired)
			},
			wantErr: errNoMatch,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, addr := newTestDaemon(t)
			prs := tt.setup(t, d)

			body, err := fetch(t.Context(), prs, []candidate{{addr: addr}})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("fetch error = %v, want %v", err, tt.wantErr)
			}
			if string(body) != tt.wantBody {
				t.Errorf("body = %q, want %q", body, tt.wantBody)
			}
		})
	}
}

// A fetch reaches every host on the LAN, so any per paste penalty for a failed
// exchange would destroy bystanders' pastes during normal use. This is why there
// is no per paste guess budget.
func TestFanOutDoesNotChargeBystanders(t *testing.T) {
	d, addr := newTestDaemon(t)
	addTestPaste(t, d, "acid-acorn-acre", "not yours")
	wrong, err := derivePRS("blaze-cobra-drift")
	if err != nil {
		t.Fatal(err)
	}

	for range 3 {
		if _, err := fetch(t.Context(), wrong, []candidate{{addr: addr}}); !errors.Is(err, errNoMatch) {
			t.Fatalf("fetch error = %v, want errNoMatch", err)
		}
	}
	for _, p := range d.store.list() {
		if p.Burned || p.Gets != 0 {
			t.Errorf("bystander paste changed: burned=%v gets=%d", p.Burned, p.Gets)
		}
	}

	right, err := derivePRS("acid-acorn-acre")
	if err != nil {
		t.Fatal(err)
	}
	if body, err := fetch(t.Context(), right, []candidate{{addr: addr}}); err != nil || string(body) != "not yours" {
		t.Fatalf("fetch = %q, %v", body, err)
	}
}

// Regression for the burn attack, where the client named the paste its failed
// confirmation was charged to and could destroy any paste in five connections.
func TestGarbageConfirmationDestroysNothing(t *testing.T) {
	d, addr := newTestDaemon(t)
	prs := addTestPaste(t, d, "acid-acorn-acre", "still here")

	// One short of rateBurst, leaving the honest fetch below a token.
	for range rateBurst - 1 {
		if err := sendGarbageConfirmation(addr); err != nil {
			t.Fatal(err)
		}
	}
	body, err := fetch(t.Context(), prs, []candidate{{addr: addr}})
	if err != nil || string(body) != "still here" {
		t.Fatalf("fetch = %q, %v", body, err)
	}
}

// sendGarbageConfirmation runs a valid handshake up to the confirmation step,
// then sends a tag that cannot match anything.
func sendGarbageConfirmation(addr string) error {
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer raw.Close()

	conn := tls.Client(raw, &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		NextProtos:         []string{alpnProto},
	})
	if err := conn.Handshake(); err != nil {
		return err
	}
	if err := conn.SetDeadline(time.Now().Add(pakeTimeout)); err != nil {
		return err
	}
	sid, err := channelBinding(conn)
	if err != nil {
		return err
	}
	leaf := conn.ConnectionState().PeerCertificates[0]
	side := newPakeSide([]byte("not a real password"), channelID(hostID(leaf.RawSubjectPublicKeyInfo)), sid)
	if err := writeFrame(conn, append([]byte{wireVersion}, side.share...)); err != nil {
		return err
	}
	if _, err := readFrame(conn, maxOfferLen); err != nil {
		return err
	}
	if err := writeFrame(conn, make([]byte, macLen)); err != nil {
		return err
	}
	// Blocks until the server hangs up, so the attempt is fully processed before
	// the next one starts.
	readFrame(conn, maxFrame)
	return nil
}

func TestRateLimitClosesTheConnection(t *testing.T) {
	_, addr := newTestDaemon(t)
	for range rateBurst {
		if err := sendGarbageConfirmation(addr); err != nil {
			t.Fatal(err)
		}
	}
	if err := sendGarbageConfirmation(addr); err == nil {
		t.Error("the daemon kept answering past the burst allowance")
	}
}

func TestHandshakeRejectsMalformedInput(t *testing.T) {
	tests := []struct {
		name  string
		hello []byte
	}{
		{"empty hello", nil},
		{"short hello", make([]byte, helloLen-1)},
		{"wrong version", append([]byte{wireVersion + 1}, make([]byte, pointLen)...)},
		{"identity share", append([]byte{wireVersion}, make([]byte, pointLen)...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, addr := newTestDaemon(t)
			raw, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()

			conn := tls.Client(raw, &tls.Config{
				MinVersion:         tls.VersionTLS13,
				InsecureSkipVerify: true,
				NextProtos:         []string{alpnProto},
			})
			if err := conn.HandshakeContext(t.Context()); err != nil {
				t.Fatal(err)
			}
			conn.SetDeadline(time.Now().Add(pakeTimeout))
			if err := writeFrame(conn, tt.hello); err != nil {
				t.Fatal(err)
			}
			if _, err := readFrame(conn, maxOfferLen); err == nil {
				t.Error("the server answered malformed input")
			}
		})
	}
}

func TestReadFrameRejectsOversizedFrames(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go writeFrame(client, make([]byte, 64))
	if _, err := readFrame(server, 32); !errors.Is(err, errProtocol) {
		t.Errorf("readFrame error = %v, want errProtocol", err)
	}
}

// Posting and fetching on one machine cannot go through discovery, since a
// daemon never learns about itself from its own announcements.
func TestPeersIncludesThisMachine(t *testing.T) {
	d, _ := newTestDaemon(t)
	srv := newControlServer(t, d)

	var out struct {
		Peers []peer `json:"peers"`
	}
	if err := srv.do(t.Context(), "GET", "/peers", "", &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Peers) == 0 || out.Peers[0].HostID != d.hostID {
		t.Fatalf("peers = %+v, want this machine first", out.Peers)
	}
	if want := net.JoinHostPort("127.0.0.1", strconv.Itoa(d.port)); out.Peers[0].Addr != want {
		t.Errorf("own address = %q, want %q", out.Peers[0].Addr, want)
	}
}

func TestControlPlaneRoundTrip(t *testing.T) {
	d, _ := newTestDaemon(t)
	srv := newControlServer(t, d)

	var posted struct {
		Code string `json:"code"`
	}
	if err := srv.do(context.Background(), "POST", "/pastes?label=demo", "hello", &posted); err != nil {
		t.Fatal(err)
	}
	if _, err := canonical(posted.Code); err != nil {
		t.Fatalf("tp post returned a code that tp get cannot parse: %v", err)
	}

	var listed struct {
		Pastes []*paste `json:"pastes"`
	}
	if err := srv.do(context.Background(), "GET", "/pastes", "", &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Pastes) != 1 || listed.Pastes[0].Label != "demo" {
		t.Fatalf("list returned %+v", listed.Pastes)
	}

	prs, err := derivePRS(posted.Code)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.do(context.Background(), "DELETE", "/pastes/"+hex.EncodeToString(prs), "", nil); err != nil {
		t.Fatal(err)
	}
	if got := len(d.store.list()); got != 0 {
		t.Errorf("%d pastes remain after delete, want 0", got)
	}
}

func TestControlPlaneRejectsBadInput(t *testing.T) {
	tests := []struct {
		name string
		path string
		body string
	}{
		{"oversized paste", "/pastes", string(make([]byte, maxPasteSize+1))},
		{"negative ttl", "/pastes?ttl=-1h", "x"},
		{"ttl over the cap", "/pastes?ttl=48h", "x"},
		{"unparseable ttl", "/pastes?ttl=soon", "x"},
		{"negative max_gets", "/pastes?max_gets=-1", "x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, _ := newTestDaemon(t)
			srv := newControlServer(t, d)
			if err := srv.do(context.Background(), "POST", tt.path, tt.body, nil); err == nil {
				t.Error("the daemon accepted it")
			}
		})
	}
}
