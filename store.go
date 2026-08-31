package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

const (
	maxPasteSize = 1 << 20
	maxPastes    = 256

	// Pad offers into power of two buckets so their size reveals a range, not
	// the exact number of live pastes.
	minCandidates = 4
	maxCandidates = 512
	defaultTTL    = time.Hour
	maxTTL        = 24 * time.Hour
	sweepInterval = 30 * time.Second
)

var (
	errTooMany   = errors.New("too many pastes on this machine")
	errCollision = errors.New("code collision")
)

// paste stores the payload and its scrypt hardened PAKE secret, never the
// user facing code.
type paste struct {
	Label     string    `json:"label,omitempty"`
	Size      int       `json:"size"`
	ExpiresAt time.Time `json:"expires_at"`
	MaxGets   int       `json:"max_gets,omitempty"`
	Gets      int       `json:"gets"`
	Burned    bool      `json:"burned"`

	prs  []byte
	data []byte
}

type store struct {
	mu sync.Mutex
	m  map[string]*paste

	// Random PAKE input used to pad offers without adding a real paste.
	decoy []byte
}

func newStore() *store {
	decoy := make([]byte, scryptLen)
	if _, err := rand.Read(decoy); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return &store{m: make(map[string]*paste), decoy: decoy}
}

func pasteKey(prs []byte) string { return hex.EncodeToString(prs) }

func (s *store) add(p *paste) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.m) >= maxPastes {
		return errTooMany
	}
	// Preserve the existing paste and let the caller generate another code.
	if _, taken := s.m[pasteKey(p.prs)]; taken {
		return errCollision
	}
	s.m[pasteKey(p.prs)] = p
	return nil
}

// candidates returns active PAKE secrets plus shuffled decoys up to the padded
// offer size.
func (s *store) candidates() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	out := make([][]byte, 0, minCandidates)
	for _, p := range s.m {
		if p.Burned || now.After(p.ExpiresAt) {
			continue
		}
		out = append(out, p.prs)
	}
	for target := paddedCount(len(out)); len(out) < target; {
		out = append(out, s.decoy)
	}
	// Shuffle so decoy positions do not reveal the number of live entries.
	for i := len(out) - 1; i > 0; i-- {
		j := randIndex(i + 1)
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// paddedCount returns the smallest power of two bucket with room for a decoy.
func paddedCount(live int) int {
	n := minCandidates
	for n < live+1 && n < maxCandidates {
		n *= 2
	}
	return n
}

// take records a verified fetch and returns a copy of the payload. The copy
// remains valid if the stored paste is later burned or swept.
func (s *store) take(prs []byte) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.m[pasteKey(prs)]
	if p == nil || p.Burned || time.Now().After(p.ExpiresAt) {
		return nil
	}
	p.Gets++
	// Reserve space for the AEAD tag so seal can encrypt this copy in place.
	body := make([]byte, len(p.data), len(p.data)+aeadOverhead)
	copy(body, p.data)
	if p.MaxGets > 0 && p.Gets >= p.MaxGets {
		burn(p)
	}
	return body
}

// burn clears the payload but retains its metadata for listing. The caller must
// hold the store lock.
func burn(p *paste) {
	clear(p.data)
	p.data = nil
	p.Burned = true
}

func (s *store) list() []*paste {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*paste, 0, len(s.m))
	for _, p := range s.m {
		out = append(out, p)
	}
	return out
}

func (s *store) del(prs []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := pasteKey(prs)
	p := s.m[key]
	if p == nil {
		return false
	}
	burn(p)
	delete(s.m, key)
	return true
}

func (s *store) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, p := range s.m {
		burn(p)
		delete(s.m, key)
	}
}

func (s *store) sweep() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, p := range s.m {
		if now.After(p.ExpiresAt) {
			burn(p)
			delete(s.m, key)
		}
	}
}
