package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type health struct {
	Peers      []peer   `json:"peers"`
	Diagnostic string   `json:"diagnostic"`
	Packets    int64    `json:"packets"`
	AnyPackets int64    `json:"any_packets"`
	Uptime     string   `json:"uptime"`
	Interfaces []string `json:"interfaces"`
}

// cmdDoctor checks multicast reception and known platform specific discovery failures.
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

	// The first peer is always the local daemon.
	others := len(h.Peers) - 1
	fmt.Printf("peers:       %d\n", others)
	for _, p := range h.Peers[1:] {
		fmt.Printf("  %s  %s  %s\n", p.HostID, p.Hostname, p.Addr)
	}

	if isWSL() {
		mode := "mirrored"
		if wslNAT(interfacesOrNil()) {
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

// doctorFix applies fixes that do not require user action.
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

// macOS 15 records local network permission against the binary's signing
// identifier. Sign tp with a stable identifier before requesting access.
// The child daemon inherits the CLI's identity.
func fixDarwin(ctx context.Context) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if err := signSelf(ctx, self); err != nil {
		return err
	}

	// Restart so the daemon joins the multicast group under the new identity.
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

// macOS stores local network permission against this identifier, so it must
// remain stable across upgrades.
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

// watchMulticast listens directly to distinguish a blocked multicast socket
// from a quiet network.
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

// Send the probe from the foreground process so macOS presents an access prompt
// instead of a background notification.
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
