package main

import (
	"net"
	"slices"
	"strings"
	"sync"
	"time"
)

// Excluding virtual and tunnel interfaces avoids duplicate mDNS announcements
// and keeps pastes off VPN links, which are outside the LAN scope.
var excludedIfacePrefixes = []string{
	"docker", "br-", "veth", "vboxnet", "tun", "utun", "wg", "awdl", "llw",
}

const ifaceRefresh = 20 * time.Second

// netFilter is the set of interfaces tp will work on, both for mDNS and for
// deciding which inbound connections to answer. The daemon outlives every
// network a laptop joins, so the set is re-read on a timer.
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

// refresh reports whether the usable set changed.
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

// serves reports whether a connection arriving on this local address should be
// answered. Loopback always qualifies, so a machine can fetch its own paste.
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

// usableInterfaces returns interfaces that are up, multicast capable, not
// loopback, not excluded by name, and carrying a routable IPv4 address.
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
