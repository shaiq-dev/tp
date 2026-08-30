package main

import (
	"net"
	"testing"
)

func TestLooksLikeWSL(t *testing.T) {
	for _, tc := range []struct {
		release string
		want    bool
	}{
		{"5.15.167.4-microsoft-standard-WSL2", true},
		{"6.6.87.2-microsoft-standard-WSL2+", true},
		{"6.10.0-linuxkit", false},
		{"6.8.0-45-generic", false},
		{"", false},
	} {
		if got := looksLikeWSL(tc.release); got != tc.want {
			t.Errorf("looksLikeWSL(%q) = %v, want %v", tc.release, got, tc.want)
		}
	}
}

func TestWSLNAT(t *testing.T) {
	// wslNAT reads addresses off real interfaces, so the cases that matter are
	// covered through the range check it depends on.
	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{"172.28.144.13", true},  // the WSL virtual switch
		{"172.16.0.1", true},     // first address of the range
		{"172.31.255.254", true}, // last
		{"192.168.1.55", false},  // mirrored, sharing the host's LAN
		{"10.0.0.4", false},
		{"172.15.0.1", false}, // just outside
		{"172.32.0.1", false},
	} {
		if got := wslNATRange.Contains(net.ParseIP(tc.ip)); got != tc.want {
			t.Errorf("wslNATRange.Contains(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestWSLNATNoAddresses(t *testing.T) {
	if wslNAT(nil) {
		t.Error("wslNAT(nil) = true, want false: no interfaces is not evidence of NAT")
	}
}
