package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"
)

// Handshake cost grows with the number of pastes a host serves, since the server
// answers for all of them. These benchmarks produce the published scaling
// numbers.

func BenchmarkDerivePRS(b *testing.B) {
	for b.Loop() {
		if _, err := derivePRS("acid-acorn-acre"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkServerOffer(b *testing.B) {
	for _, n := range []int{1, 40, maxPastes} {
		b.Run(fmt.Sprintf("%d-pastes", n), func(b *testing.B) {
			s := storeWithPastes(b, n)
			sid, ci := make([]byte, 32), channelID("HOST12345678")
			peer := newPakeSide([]byte("client"), ci, sid)
			b.ResetTimer()
			for b.Loop() {
				for _, prs := range s.candidates() {
					side := newPakeSide(prs, ci, sid)
					if err := side.finish(peer.share, sid); err != nil {
						b.Fatal(err)
					}
					_ = side.serverTag()
				}
			}
		})
	}
}

func BenchmarkClientMatch(b *testing.B) {
	for _, n := range []int{1, 40} {
		b.Run(fmt.Sprintf("%d-candidates", n), func(b *testing.B) {
			sid, ci := make([]byte, 32), channelID("HOST12345678")
			client := newPakeSide(randomPRS(b), ci, sid)
			offer := []byte{byte(n >> 8), byte(n)}
			for i := range n {
				server := newPakeSide(randomPRS(b), ci, sid)
				if err := server.finish(client.share, sid); err != nil {
					b.Fatal(err)
				}
				offer = append(offer, server.share...)
				offer = append(offer, server.serverTag()...)
				_ = i
			}
			b.ResetTimer()
			for b.Loop() {
				matchOffer(client, sid, offer)
			}
		})
	}
}

func TestFanOutAcrossManyHosts(t *testing.T) {
	tests := []struct {
		name          string
		hosts         int
		pastesPerHost int
	}{
		{"busy office", 100, 40},
		{"large campus", 1000, 125},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fanOutCase(t, tt.hosts, tt.pastesPerHost)
		})
	}
}

// fanOutCase times one fetch across every host, with the holder last so nothing
// short circuits.
//
// Only the fetched paste carries a full 1 MiB body. BenchmarkPasteSize shows the
// handshake never touches paste contents, and a hundred thousand real megabyte
// pastes do not fit in one process. TestFullMachineMemory covers the memory.
func fanOutCase(t *testing.T, hosts, pastesPerHost int) {
	t.Helper()
	if testing.Short() {
		t.Skip("stands up many listeners")
	}

	t.Setenv("XDG_DATA_HOME", t.TempDir())
	cert, err := loadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	wanted := randomPRS(t)
	body := make([]byte, maxPasteSize)
	if _, err := rand.Read(body); err != nil {
		t.Fatal(err)
	}
	filler := []byte("x")

	cands := make([]candidate, 0, hosts)
	for i := range hosts {
		l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
			NextProtos:   []string{alpnProto},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()

		d := &daemon{
			store:   newStore(),
			limiter: newLimiter(),
			peers:   newPeerTable(),
			net:     newNetFilter(),
			hostID:  hostID(cert.Leaf.RawSubjectPublicKeyInfo),
			port:    l.Addr().(*net.TCPAddr).Port,
		}
		for j := range pastesPerHost {
			prs, data := randomPRS(t), filler
			if i == hosts-1 && j == 0 {
				prs, data = wanted, body
			}
			if err := d.store.add(&paste{
				Size:      len(data),
				ExpiresAt: time.Now().Add(time.Hour),
				prs:       prs,
				data:      data,
			}); err != nil {
				t.Fatal(err)
			}
		}
		go d.serveData(t.Context(), l)
		cands = append(cands, candidate{addr: l.Addr().String()})
	}

	start := time.Now()
	got, err := fetch(t.Context(), wanted, cands)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("fetched %d bytes, want %d", len(got), len(body))
	}

	candidates := paddedCount(pastesPerHost)
	offer := 2 + candidates*(pointLen+macLen)
	t.Logf("%d hosts x %d pastes, holder last, %d MiB payload: %v",
		hosts, pastesPerHost, len(body)>>20, elapsed.Round(time.Millisecond))
	t.Logf("  fan out width %d, %d padded candidates, offer %d B per host, %d KiB in total",
		fanOut(len(cands)), candidates, offer, hosts*offer>>10)
}

// The largest load the caps allow, which decides whether a laptop can serve
// one.
func TestFullMachineMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates a few hundred MiB")
	}
	body := make([]byte, maxPasteSize)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	s := newStore()
	for range maxPastes {
		data := make([]byte, len(body))
		copy(data, body)
		if err := s.add(&paste{
			Size:      len(data),
			ExpiresAt: time.Now().Add(time.Hour),
			prs:       randomPRS(t),
			data:      data,
		}); err != nil {
			t.Fatal(err)
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&after)

	t.Logf("%d pastes of %d MiB each: %d MiB held",
		maxPastes, maxPasteSize>>20, (after.HeapAlloc-before.HeapAlloc)>>20)
	runtime.KeepAlive(s)
}

// Handshake cost is independent of paste size, which is what lets fanOutCase use
// small filler bodies.
func BenchmarkPasteSize(b *testing.B) {
	for _, size := range []int{1, maxPasteSize} {
		b.Run(fmt.Sprintf("%d-byte-paste", size), func(b *testing.B) {
			sid, ci := make([]byte, 32), channelID("HOST12345678")
			s := newStore()
			prs := randomPRS(b)
			if err := s.add(&paste{
				ExpiresAt: time.Now().Add(time.Hour),
				prs:       prs,
				data:      make([]byte, size),
			}); err != nil {
				b.Fatal(err)
			}
			peer := newPakeSide(randomPRS(b), ci, sid)
			b.ResetTimer()
			for b.Loop() {
				for _, c := range s.candidates() {
					side := newPakeSide(c, ci, sid)
					if err := side.finish(peer.share, sid); err != nil {
						b.Fatal(err)
					}
					_ = side.serverTag()
				}
			}
		})
	}
}

func storeWithPastes(tb testing.TB, n int) *store {
	tb.Helper()
	s := newStore()
	for range n {
		if err := s.add(&paste{
			ExpiresAt: time.Now().Add(time.Hour),
			prs:       randomPRS(tb),
			data:      []byte("x"),
		}); err != nil {
			tb.Fatal(err)
		}
	}
	return s
}

// randomPRS stands in for a scrypt output, which the PAKE cannot distinguish and
// which keeps these tests off a 37 ms key derivation per paste.
func randomPRS(tb testing.TB) []byte {
	tb.Helper()
	prs := make([]byte, scryptLen)
	if _, err := rand.Read(prs); err != nil {
		tb.Fatal(err)
	}
	return prs
}
