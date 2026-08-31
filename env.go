package main

import (
	"net"
	"os"
	"runtime"
	"strings"
)

// Discovery needs platform-specific handling on WSL2 and macOS.
// WSL2 NAT isolates multicast from the LAN, while macOS 15 ties local network
// permission to a stable code signing identity.

const (
	osReleasePath = "/proc/sys/kernel/osrelease"
	osDarwin      = "darwin"
)

// WSL assigns NAT mode guests from this subnet.
var wslNATRange = net.IPNet{IP: net.IPv4(172, 16, 0, 0), Mask: net.CIDRMask(12, 32)}

func isWSL() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	b, err := os.ReadFile(osReleasePath)
	if err != nil {
		return false
	}
	return looksLikeWSL(string(b))
}

func looksLikeWSL(release string) bool {
	r := strings.ToLower(release)
	return strings.Contains(r, "microsoft") || strings.Contains(r, "wsl")
}

// wslNAT reports whether all usable IPv4 addresses belong to WSL's NAT subnet.
// An address outside this range indicates mirrored networking.
func wslNAT(ifaces []net.Interface) bool {
	seen := false
	for _, ifi := range ifaces {
		ip := ip4(ifi)
		if ip == nil {
			continue
		}
		seen = true
		if !wslNATRange.Contains(ip) {
			return false
		}
	}
	return seen
}

// discoveryAdvice returns platform specific fixes for failed multicast discovery.
func discoveryAdvice() []string {
	switch {
	case isWSL() && wslNAT(mustInterfaces()):
		return []string{
			"WSL is in NAT mode, so multicast never reaches your LAN. Switch to mirrored networking:",
			"  1. in Windows, put this in %UserProfile%\\.wslconfig",
			"       [wsl2]",
			"       networkingMode=mirrored",
			"  2. wsl --shutdown",
			"  3. if inbound still fails, in an admin PowerShell:",
			"       Set-NetFirewallHyperVVMSetting -Name '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}' -DefaultInboundAction Allow",
		}
	case runtime.GOOS == osDarwin:
		return []string{
			"macOS 15 and later records local network access against a code signing",
			"identity, and the Go linker signs every binary as a.out, so a plain tp has",
			"nothing to grant. Sign it, restart the daemon and ask:",
			"  tp doctor --fix",
			"then allow tp when asked, or in System Settings, Privacy and Security,",
			"Local Network. tccutil has no LocalNetwork service, so the pane is the only",
			"place the decision can be changed.",
		}
	}
	return nil
}

func mustInterfaces() []net.Interface {
	ifaces, err := usableInterfaces()
	if err != nil {
		return nil
	}
	return ifaces
}
