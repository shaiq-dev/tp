package main

import (
	"net"
	"slices"
	"strings"
	"sync"
	"time"
)

// Ignore virtual and tunnel interfaces to avoid duplicate mDNS announcements
// and exposing pastes outside the local LAN.
var excludedIfacePrefixes = []string{
	"docker", "br-", "veth", "vboxnet", "tun", "utun", "wg", "awdl", "llw",
}

const ifaceRefresh = 20 * time.Second

// netFilter tracks the interfaces allowed for mDNS and inbound data connections.
// It is refreshed because the daemon may outlive the current network.
type netFilter struct {
	mu     sync.RWMutex
	ifaces []net.Interface
	addrs  map[string]bool
}

func newNetFilter() *netFilter {
	f := &netFilter{addrs: make(map[string]bool)}
	f.refresh()
	return f
}

// refresh updates the filter when the usable IPv4 address set changes.
func (f *netFilter) refresh() bool {
	ifaces, _ := usableInterfaces()
	addrs := make(map[string]bool, len(ifaces))
	for _, ifi := range ifaces {
		if ip := ip4(ifi); ip != nil {
			addrs[ip.String()] = true
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if sameAddrs(f.addrs, addrs) {
		return false
	}
	f.ifaces, f.addrs = ifaces, addrs
	return true
}

func (f *netFilter) interfaces() []net.Interface {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return slices.Clone(f.ifaces)
}

func (f *netFilter) isOwnAddr(ip string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.addrs[ip]
}

// serves accepts connections on selected interfaces and loopback.
func (f *netFilter) serves(local net.Addr) bool {
	host, _, err := net.SplitHostPort(local.String())
	if err != nil {
		return false
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	return f.isOwnAddr(host)
}

func ifaceNames(ifaces []net.Interface) []string {
	out := make([]string, 0, len(ifaces))
	for _, ifi := range ifaces {
		name := ifi.Name
		if ip := ip4(ifi); ip != nil {
			name += " " + ip.String()
		}
		out = append(out, name)
	}
	return out
}

func sameAddrs(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// usableInterfaces returns multicast capable LAN interfaces with a usable IPv4
// address.
func usableInterfaces() ([]net.Interface, error) {
	all, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []net.Interface
	for _, ifi := range all {
		const want = net.FlagUp | net.FlagMulticast
		if ifi.Flags&want != want || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if excluded(ifi.Name) || ip4(ifi) == nil {
			continue
		}
		out = append(out, ifi)
	}
	if len(out) == 0 {
		return nil, errNoInterface
	}
	return out, nil
}

func excluded(name string) bool {
	for _, prefix := range excludedIfacePrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func ip4(ifi net.Interface) net.IP {
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if v4 := n.IP.To4(); v4 != nil && !v4.IsLinkLocalUnicast() {
			return v4
		}
	}
	return nil
}
