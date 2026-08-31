package main

import (
	"sync"
	"time"
)

// Rate limiting has two scopes. The per IP bucket protects handshake capacity
// from a noisy peer, but it is not a security boundary because a LAN attacker
// can use multiple addresses. The global bucket is the online guessing limit.
//
// The burst allowance leaves room for fan out and mistyped codes. Repeated
// confirmation failures temporarily block the source address. All state is
// in memory and resets with the daemon.
const (
	rateBurst       = 20
	ratePerMinute   = 20
	blockAfter      = 50
	blockWindow     = 10 * time.Minute
	blockFor        = time.Hour
	globalBurst     = 60
	globalPerSecond = 10
)

type limiter struct {
	mu     sync.Mutex
	ip     map[string]*ipState
	global bucket
}

// Use monotonic elapsed time so wall clock changes do not affect token refill.
type bucket struct {
	tokens float64
	last   time.Time
}

func (b *bucket) take(now time.Time, burst, perSecond float64) bool {
	if b.last.IsZero() {
		b.tokens, b.last = burst, now
	}
	b.tokens = min(burst, b.tokens+now.Sub(b.last).Seconds()*perSecond)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type ipState struct {
	bucket
	lastSeen time.Time
	failures []time.Time
	blocked  time.Time
}

func newLimiter() *limiter { return &limiter{ip: make(map[string]*ipState)} }

// allowPeer enforces per IP admission before any TLS work begins.
func (l *limiter) allowPeer(addr string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	s, ok := l.ip[addr]
	if !ok {
		s = &ipState{}
		l.ip[addr] = s
	}
	s.lastSeen = now
	if now.Before(s.blocked) {
		return false
	}
	return s.take(now, rateBurst, ratePerMinute/60.0)
}

// Charge the global budget immediately before sending a testable offer. Charging
// earlier would let a plain TCP flood consume it without making password guesses.
func (l *limiter) allowExchange() bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.global.take(now, globalBurst, globalPerSecond)
}

// fail blocks an address after enough confirmation failures within blockWindow.
func (l *limiter) fail(addr string) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	s, ok := l.ip[addr]
	if !ok {
		return
	}
	recent := make([]time.Time, 0, len(s.failures)+1)
	for _, t := range s.failures {
		if now.Sub(t) < blockWindow {
			recent = append(recent, t)
		}
	}
	recent = append(recent, now)
	s.failures = recent
	if len(s.failures) >= blockAfter {
		s.blocked = now.Add(blockFor)
		s.failures = nil
	}
}

// sweep removes inactive per IP state to keep the map bounded.
func (l *limiter) sweep() {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	for addr, s := range l.ip {
		if now.After(s.blocked) && now.Sub(s.lastSeen) > blockWindow {
			delete(l.ip, addr)
		}
	}
}
