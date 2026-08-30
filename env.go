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

const osReleasePath = "/proc/sys/kernel/osrelease"

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

// launchAgentPath is where the installer puts the agent. Its presence is the
// signal that the daemon should be started through launchd rather than forked.
func launchAgentPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home + "/Library/LaunchAgents/sh.tp.daemon.plist"
}

func launchAgentInstalled() bool {
	if runtime.GOOS != "darwin" {
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
	case runtime.GOOS == "darwin" && !launchAgentInstalled():
		return []string{
			"macOS 15 and later records local network access per code signing identity,",
			"and the Go linker signs every binary as a.out, so there is nothing to grant.",
			"Sign the daemon as sh.tp.daemon and run it under launchd:",
			"  tp doctor --fix",
		}
	case runtime.GOOS == "darwin":
		return []string{
			"The daemon is installed and signed, so the decision is yours to make:",
			"  System Settings, Privacy and Security, Local Network, enable tp",
			"If tp is not listed there, an older denial is cached against a.out:",
			"  tccutil reset LocalNetwork && tp doctor --fix",
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
