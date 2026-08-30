package main

import (
	"testing"
	"time"
)

func TestLimiterAllow(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(l *limiter)
		addr    string
		want    bool
	}{
		{"first request", func(*limiter) {}, "1.2.3.4", true},
		{
			name:    "burst exhausted",
			prepare: func(l *limiter) { spend(l, "1.2.3.4", rateBurst) },
			addr:    "1.2.3.4",
			want:    false,
		},
		{
			name:    "limits are per IP",
			prepare: func(l *limiter) { spend(l, "1.2.3.4", rateBurst) },
			addr:    "5.6.7.8",
			want:    true,
		},
		{
			name: "blocked after repeated failures",
			prepare: func(l *limiter) {
				l.allowPeer("1.2.3.4")
				for range blockAfter {
					l.fail("1.2.3.4")
				}
			},
			addr: "1.2.3.4",
			want: false,
		},
		{
			name: "old failures fall out of the window",
			prepare: func(l *limiter) {
				l.allowPeer("1.2.3.4")
				l.ip["1.2.3.4"].failures = staleFailures(blockAfter - 1)
				l.fail("1.2.3.4")
			},
			addr: "1.2.3.4",
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := newLimiter()
			tt.prepare(l)
			if got := l.allowPeer(tt.addr); got != tt.want {
				t.Errorf("allow(%s) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

func spend(l *limiter, addr string, n int) {
	for range n {
		l.allowPeer(addr)
	}
}

func staleFailures(n int) []time.Time {
	out := make([]time.Time, n)
	for i := range out {
		out[i] = time.Now().Add(-2 * blockWindow)
	}
	return out
}

func TestLimiterSweep(t *testing.T) {
	l := newLimiter()
	l.allowPeer("1.2.3.4")
	l.ip["1.2.3.4"].lastSeen = time.Now().Add(-2 * blockWindow)
	l.allowPeer("5.6.7.8")

	l.sweep()
	if _, ok := l.ip["1.2.3.4"]; ok {
		t.Error("sweep kept an idle IP")
	}
	if _, ok := l.ip["5.6.7.8"]; !ok {
		t.Error("sweep dropped an active IP")
	}
}
