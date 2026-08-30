package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// doctor answers "why did discovery not find the other machine", which is
// otherwise a guess between three unrelated causes: this network, WSL NAT, and
// the macOS local network gate.

type health struct {
	Peers      []peer   `json:"peers"`
	Diagnostic string   `json:"diagnostic"`
	Packets    int64    `json:"packets"`
	AnyPackets int64    `json:"any_packets"`
	Uptime     string   `json:"uptime"`
	Interfaces []string `json:"interfaces"`
}

func cmdDoctor(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	fix := fs.Bool("fix", false, "apply what this platform needs, where tp can do it itself")
	listen := fs.Duration("listen", 0, "watch the multicast group for this long and report what arrives")
	quiet := fs.Bool("quiet", false, "only print when something needs attention")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *fix {
		return doctorFix(ctx, *quiet)
	}
	if *listen > 0 {
		return watchMulticast(ctx, *listen)
	}
	return report(ctx)
}

func report(ctx context.Context) error {
	fmt.Print(readBuildInfo())

	var h health
	if err := control(ctx, http.MethodGet, "/peers?wait=3s", nil, &h); err != nil {
		fmt.Println("daemon:      not answering:", err)
		return nil
	}

	fmt.Printf("daemon:      up %s\n", h.Uptime)
	fmt.Printf("interfaces:  %v\n", h.Interfaces)
	fmt.Printf("mdns in:     %d packets, %d of them from other machines\n", h.AnyPackets, h.Packets)

	// The daemon lists itself, so one peer means nobody else was heard.
	others := len(h.Peers) - 1
	fmt.Printf("peers:       %d\n", others)
	for _, p := range h.Peers[1:] {
		fmt.Printf("  %s  %s  %s\n", p.HostID, p.Hostname, p.Addr)
	}

	if launchAgentInstalled() {
		fmt.Println("launch agent: present, and it stops the daemon being granted access")
		fmt.Println("              remove it with tp doctor --fix")
	}
	if isWSL() {
		mode := "mirrored"
		if wslNAT(mustInterfaces()) {
			mode = "nat"
		}
		fmt.Printf("wsl:         %s networking\n", mode)
	}

	if h.AnyPackets > 0 && others > 0 {
		fmt.Println("\nDiscovery is working.")
		return nil
	}
	if h.AnyPackets > 0 {
		fmt.Println("\nThis socket can receive multicast, and no other tp host has announced itself.")
		fmt.Println("Start tp on the other machine and run this again.")
		if h.Packets == 0 {
			fmt.Println("Nothing at all has been heard from another machine, so if tp is")
			fmt.Println("already running there, that side is the one to look at:")
			fmt.Println("  tp doctor           on the other machine")
		}
		return nil
	}

	fmt.Println("\nNo multicast is arriving, so discovery cannot work.")
	for _, line := range discoveryAdvice() {
		fmt.Println(line)
	}
	return nil
}

// doctorFix does the part of the advice that is ours to do rather than yours.
// Only macOS has one.
func doctorFix(ctx context.Context, quiet bool) error {
	if runtime.GOOS != osDarwin {
		if !quiet {
			for _, line := range discoveryAdvice() {
				fmt.Println(line)
			}
		}
		return nil
	}
	return fixDarwin(ctx)
}

// fixDarwin gives tp a code signing identity, because that is what macOS 15 and
// later records a local network decision against, and the Go linker signs every
// binary as a.out. Then it restarts the daemon and asks, so the decision is made
// against the new identity.
//
// The daemon is forked by the command and inherits the command's identity, so
// signing the one binary covers both. An earlier version of this installed a
// launch agent instead. That was wrong: a launchd job has no responsible app, so
// its request is denied whatever the pane says, and the agent is removed here.
func fixDarwin(ctx context.Context) error {
	if err := removeLegacyAgent(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "tp:", err)
	}

	self, err := os.Executable()
	if err != nil {
		return err
	}
	if err := signSelf(ctx, self); err != nil {
		return err
	}

	// The daemon holds the multicast socket, and the decision is evaluated when
	// it joins, so the old one has to go before we ask.
	_ = exec.CommandContext(ctx, "pkill", "-f", "tp daemon").Run()

	fmt.Printf("signed %s as %s\n", self, cliID)
	if err := probeMulticast(); err != nil {
		fmt.Fprintln(os.Stderr, "tp: could not send a probe:", err)
	}
	fmt.Println("macOS should now ask whether tp may find devices on local networks. Allow it.")
	fmt.Println("If nothing appears, the decision is already recorded:")
	fmt.Println("  open 'x-apple.systempreferences:com.apple.preference.security?Privacy_LocalNetwork'")
	fmt.Println("Then run tp doctor.")
	return nil
}

// cliID is the code signing identifier, and what shows up in Privacy and
// Security. It has to be stable across upgrades or the decision is lost.
const cliID = "sh.tp"

func signSelf(ctx context.Context, bin string) error {
	if _, err := exec.LookPath("codesign"); err != nil {
		return fmt.Errorf("codesign is not installed, so tp keeps the identifier "+
			"a.out and macOS cannot record a decision for it. Install the Xcode "+
			"command line tools and run tp doctor --fix again: %w", err)
	}
	//nolint:gosec // The identifier is a constant and bin is os.Executable.
	out, err := exec.CommandContext(ctx, "codesign", "--force", "--sign", "-",
		"--identifier", cliID, bin).CombinedOutput()
	if err != nil {
		return fmt.Errorf("codesign: %w: %s", err, out)
	}
	return nil
}

// removeLegacyAgent undoes the launch agent that versions up to v0.0.2
// installed. Leaving it in place is worse than having nothing: the daemon runs
// under launchd, is denied local network access, and no pane toggle changes that.
func removeLegacyAgent(ctx context.Context) error {
	path := launchAgentPath()
	if path == "" {
		return nil
	}
	if !launchAgentInstalled() {
		return nil
	}

	//nolint:gosec // Both arguments are constants.
	_ = exec.CommandContext(ctx, "launchctl", "bootout", gui()+"/sh.tp.daemon").Run()
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("removing the old launch agent at %s: %w", path, err)
	}
	if home, err := os.UserHomeDir(); err == nil {
		_ = os.RemoveAll(filepath.Join(home, "Library", "Application Support", "tp"))
	}
	fmt.Println("removed the launch agent from an earlier version, which launchd could not be granted access for")
	return nil
}

func gui() string { return fmt.Sprintf("gui/%d", os.Getuid()) }

// watchMulticast joins the group in this process and reports every datagram,
// which separates "the socket cannot receive" from "nobody else is talking".
// A quiet home network with one machine on it is silent by nature, and the
// daemon's own counter cannot tell the two apart.
func watchMulticast(ctx context.Context, d time.Duration) error {
	ifaces, err := usableInterfaces()
	if err != nil {
		return err
	}
	ifi := ifaces[0]
	conn, err := net.ListenMulticastUDP("udp4", &ifi, &net.UDPAddr{IP: mdnsGroup, Port: mdnsPort})
	if err != nil {
		return fmt.Errorf("joining %s on %s: %w", mdnsGroup, ifi.Name, err)
	}
	defer func() { _ = conn.Close() }()

	fmt.Printf("listening on %s for %s, and asking once\n", ifi.Name, d)
	if err := probeMulticast(); err != nil {
		fmt.Fprintln(os.Stderr, "tp: could not send a probe:", err)
	}

	deadline := time.Now().Add(d)
	if err := conn.SetReadDeadline(deadline); err != nil {
		return err
	}
	sources := map[string]int{}
	buf := make([]byte, 9000)
	total := 0
	for time.Now().Before(deadline) {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if n > 0 {
			total++
			sources[src.IP.String()]++
		}
	}

	fmt.Printf("%d datagrams from %d sources\n", total, len(sources))
	for ip, n := range sources {
		fmt.Printf("  %-15s %d\n", ip, n)
	}
	if total == 0 {
		fmt.Println("Nothing at all, so this socket cannot receive multicast.")
		for _, line := range discoveryAdvice() {
			fmt.Println(line)
		}
	}
	return ctx.Err()
}

// probeMulticast sends one mDNS query, which is the thing macOS gates. Sending
// it from the command rather than the daemon is deliberate: a background agent's
// request arrives as a notification, and a foreground process gets an alert.
func probeMulticast() error {
	msg := dnsmessage.Message{Questions: []dnsmessage.Question{{
		Name:  dnsmessage.MustNewName(mdnsService),
		Type:  dnsmessage.TypePTR,
		Class: dnsmessage.ClassINET,
	}}}
	buf, err := msg.Pack()
	if err != nil {
		return err
	}

	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: mdnsGroup, Port: mdnsPort})
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_, err = conn.Write(buf)
	return err
}
