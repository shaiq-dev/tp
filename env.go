package main

import (
	"net"
	"os"
	"runtime"
	"strings"
)

// Two environments break discovery in ways that look like a bug in tp.
//
// WSL2 in its default NAT mode puts the VM behind a virtual switch on its own
// subnet. Multicast never leaves that switch, so announcements never reach the
// LAN and nothing on the LAN is ever heard. Mirrored mode shares the host's
// interfaces and works.
//
// macOS 15 and later gate local network access per app. A CLI's request is
// attributed to the terminal that started it, so a daemon that outlives the
// terminal has no app to attribute to and is denied without a prompt. A launch
// agent has an identity of its own, which is why the installer prefers one.

const (
	osReleasePath = "/proc/sys/kernel/osrelease"

	// osDarwin is compared against runtime.GOOS often enough that goconst asks
	// for a name.
	osDarwin = "darwin"
)

// wslNATRange is the range the WSL virtual switch hands out in NAT mode.
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

// wslNAT reports whether every usable interface sits in the NAT range, which is
// the default networkingMode. Seeing any other address means the VM is mirroring
// the host, so discovery can work and no advice is needed.
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

// launchAgentPath is where versions up to v0.0.2 put a launch agent. It is only
// looked for so it can be removed: launchd jobs have no responsible app, so the
// daemon was denied local network access whatever the settings pane said.
func launchAgentPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home + "/Library/LaunchAgents/sh.tp.daemon.plist"
}

func launchAgentInstalled() bool {
	if runtime.GOOS != osDarwin {
		return false
	}
	p := launchAgentPath()
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}

// discoveryAdvice is what to do about a network that is not delivering
// multicast, in the order worth trying. Empty when there is nothing specific to
// say and the network itself is the suspect.
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
