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

	// Offers are padded to a power of two between these, so a machine holding
	// nothing and one holding three are indistinguishable from outside.
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

// paste is one served blob. The daemon holds the scrypt hardened PAKE password
// derived from the code and never the code itself, so a memory dump yields
// nothing that can be spoken down a corridor.
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

	// decoy is a PAKE password that matches no code. Enough copies pad the offer
	// up to a power of two, so its size gives away a bucket rather than the
	// exact number of pastes held.
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
	// Overwriting would silently destroy a live paste, so the caller draws
	// another code.
	if _, taken := s.m[pasteKey(p.prs)]; taken {
		return errCollision
	}
	s.m[pasteKey(p.prs)] = p
	return nil
}

// candidates returns the PAKE passwords to run the handshake against: every live
// paste, padded out with decoys and shuffled.
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
	// Unshuffled, the decoys sit at the end and give the count back through
	// their position.
	for i := len(out) - 1; i > 0; i-- {
		j := randIndex(i + 1)
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// paddedCount rounds up to a power of two, leaving an observer the order of
// magnitude instead of the number.
func paddedCount(live int) int {
	n := minCandidates
	for n < live+1 && n < maxCandidates {
		n *= 2
	}
	return n
}

// take hands over a paste after a verified key confirmation and counts the
// fetch. The returned slice is a copy, because hitting max_gets burns the paste
// and zeroes the stored buffer, and a sweep on another goroutine can do the same
// at any moment.
func (s *store) take(prs []byte) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.m[pasteKey(prs)]
	if p == nil || p.Burned || time.Now().After(p.ExpiresAt) {
		return nil
	}
	p.Gets++
	// Spare capacity for the AEAD tag lets pakeSide.seal encrypt in place.
	body := make([]byte, len(p.data), len(p.data)+aeadOverhead)
	copy(body, p.data)
	if p.MaxGets > 0 && p.Gets >= p.MaxGets {
		burn(p)
	}
	return body
}

// burn zeroes the payload and keeps the metadata, so tp list can explain why a
// paste stopped working. The caller holds the lock.
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
