package main

import (
	"sync"
	"time"
)

// Two token buckets and a block list, all in memory so a restart forgets them.
//
// The per IP bucket stops one noisy source starving everyone. It does not bound
// guessing: on a LAN an attacker picks its own addresses, and a subnet full of
// them multiplies the limit by the size of the subnet. Its burst is a full
// minute's worth, because one tp get spends a token at every host on the
// network and a person retyping a code they got wrong would otherwise run out.
//
// The global bucket is what bounds guessing. Every exchange that reaches the
// offer is one password guess whoever it came from, so capping them together
// caps the rate however the attacker is addressed. Ten a second puts the 2^31
// codes at about seven years. Real load is nowhere near it: a thousand fetches
// an hour across a thousand machines is under a third of a second's worth.
const (
	rateBurst     = 20
	ratePerMinute = 20
	blockAfter    = 50
	blockWindow   = 10 * time.Minute
	blockFor      = time.Hour

	globalBurst     = 60
	globalPerSecond = 10
)

type limiter struct {
	mu     sync.Mutex
	ip     map[string]*ipState
	global bucket
}

// bucket runs on the monotonic clock, so time spent suspended does not refill
// it.
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

// allowPeer runs before the TLS handshake, so a flood from one source is
// rejected before it costs a handshake.
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

// allowExchange spends from the shared budget. Call it immediately before the
// offer and nowhere earlier: the offer is the oracle, and charging at accept
// lets a bare TCP flood that tests no password drain the budget.
func (l *limiter) allowExchange() bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.global.take(now, globalBurst, globalPerSecond)
}

// fail records a wrong key confirmation and blocks the IP once they pile up.
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

// sweep drops state for IPs that have gone quiet, bounding the map on a busy
// network.
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
