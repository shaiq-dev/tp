package main

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"
)

func testPaste(prs, body string, opts ...func(*paste)) *paste {
	p := &paste{
		Size:      len(body),
		ExpiresAt: time.Now().Add(time.Hour),
		prs:       []byte(prs),
		data:      []byte(body),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func expired(p *paste)           { p.ExpiresAt = time.Now().Add(-time.Second) }
func maxGets(n int) func(*paste) { return func(p *paste) { p.MaxGets = n } }

func TestStoreTake(t *testing.T) {
	tests := []struct {
		name       string
		paste      *paste
		takes      int
		wantBodies []string
		wantBurned bool
	}{
		{
			name:       "unlimited fetches",
			paste:      testPaste("a", "hello"),
			takes:      3,
			wantBodies: []string{"hello", "hello", "hello"},
		},
		{
			// Regression: burn once cleared the shared buffer before take
			// returned it, causing --burn to send NUL bytes.
			name:       "burn delivers the payload before zeroing it",
			paste:      testPaste("a", "topsecret", maxGets(1)),
			takes:      2,
			wantBodies: []string{"topsecret", ""},
			wantBurned: true,
		},
		{
			name:       "max gets of two",
			paste:      testPaste("a", "hi", maxGets(2)),
			takes:      3,
			wantBodies: []string{"hi", "hi", ""},
			wantBurned: true,
		},
		{
			name:       "expired is never served",
			paste:      testPaste("a", "stale", expired),
			takes:      1,
			wantBodies: []string{""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newStore()
			if err := s.add(tt.paste); err != nil {
				t.Fatal(err)
			}
			for i := range tt.takes {
				got := s.take(tt.paste.prs)
				if want := tt.wantBodies[i]; string(got) != want {
					t.Fatalf("take %d = %q, want %q", i+1, got, want)
				}
			}
			if tt.paste.Burned != tt.wantBurned {
				t.Errorf("Burned = %v, want %v", tt.paste.Burned, tt.wantBurned)
			}
			if tt.wantBurned && tt.paste.data != nil {
				t.Error("a burned paste still holds its buffer")
			}
		})
	}
}

// Reserving space for the AEAD tag avoids another payload sized allocation
// during sealing.
func TestTakeLeavesRoomForTheTag(t *testing.T) {
	s := newStore()
	p := testPaste("a", "hello")
	if err := s.add(p); err != nil {
		t.Fatal(err)
	}
	body := s.take(p.prs)
	if got := cap(body) - len(body); got < aeadOverhead {
		t.Errorf("take left %d bytes spare, want at least %d", got, aeadOverhead)
	}
	// Mutating the returned buffer must not modify the stored payload.
	sealed := make([]byte, 0, cap(body))
	sealed = append(sealed, body...)
	sealed = append(sealed, make([]byte, aeadOverhead)...)
	clear(sealed)
	if string(p.data) != "hello" {
		t.Errorf("the stored paste was corrupted to %q", p.data)
	}
}

func TestStoreCandidates(t *testing.T) {
	tests := []struct {
		name   string
		pastes []*paste
		want   int
	}{
		{"empty store looks like a busy one", nil, minCandidates},
		{"one live paste", []*paste{testPaste("a", "x")}, minCandidates},
		{"expired pastes are not offered", []*paste{testPaste("a", "x"), testPaste("b", "y", expired)}, minCandidates},
		{"three pastes still fit the smallest bucket", manyPastes(3), minCandidates},
		{"four pastes need room for a decoy", manyPastes(4), 2 * minCandidates},
		{"twenty pastes round up", manyPastes(20), 32},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newStore()
			for _, p := range tt.pastes {
				if err := s.add(p); err != nil {
					t.Fatal(err)
				}
			}
			if got := len(s.candidates()); got != tt.want {
				t.Errorf("len(candidates()) = %d, want %d", got, tt.want)
			}
		})
	}
}

func manyPastes(n int) []*paste {
	out := make([]*paste, n)
	for i := range out {
		out[i] = testPaste(fmt.Sprintf("prs-%d", i), "x")
	}
	return out
}

func TestPaddedCount(t *testing.T) {
	tests := []struct{ live, want int }{
		{0, 4}, {1, 4}, {3, 4}, {4, 8}, {7, 8}, {8, 16}, {255, 256}, {256, 512},
	}
	for _, tt := range tests {
		if got := paddedCount(tt.live); got != tt.want {
			t.Errorf("paddedCount(%d) = %d, want %d", tt.live, got, tt.want)
		}
		if got := paddedCount(tt.live); got <= tt.live {
			t.Errorf("paddedCount(%d) = %d, leaves no room for a decoy", tt.live, got)
		}
	}
}

func TestStoreAdd(t *testing.T) {
	s := newStore()
	if err := s.add(testPaste("a", "x")); err != nil {
		t.Fatal(err)
	}
	if err := s.add(testPaste("a", "y")); !errors.Is(err, errCollision) {
		t.Errorf("adding a duplicate password returned %v, want errCollision", err)
	}
	for i := range maxPastes - 1 {
		if err := s.add(testPaste(string(rune('A'+i%26))+string(rune(i)), "x")); err != nil {
			t.Fatalf("add %d: %v", i, err)
		}
	}
	if err := s.add(testPaste("overflow", "x")); !errors.Is(err, errTooMany) {
		t.Errorf("exceeding the cap returned %v, want errTooMany", err)
	}
}

func TestStoreSweepAndDelete(t *testing.T) {
	s := newStore()
	live, stale := testPaste("a", "live"), testPaste("b", "stale", expired)
	for _, p := range []*paste{live, stale} {
		if err := s.add(p); err != nil {
			t.Fatal(err)
		}
	}

	s.sweep()
	if got := len(s.list()); got != 1 {
		t.Fatalf("after sweep %d pastes remain, want 1", got)
	}
	if !bytes.Equal(stale.data, nil) {
		t.Error("sweep left the expired buffer in memory")
	}

	if !s.del(live.prs) {
		t.Fatal("del reported the live paste as missing")
	}
	if s.del(live.prs) {
		t.Error("del reported a deleted paste as present")
	}
	if got := len(s.list()); got != 0 {
		t.Errorf("%d pastes remain after delete, want 0", got)
	}
}
