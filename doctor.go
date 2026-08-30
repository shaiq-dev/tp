package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// doctor answers "why did discovery not find the other machine", which is
// otherwise a guess between three unrelated causes: this network, WSL NAT, and
// the macOS local network gate.

type health struct {
	Peers      []peer   `json:"peers"`
	Diagnostic string   `json:"diagnostic"`
	Packets    int64    `json:"packets"`
	Uptime     string   `json:"uptime"`
	Interfaces []string `json:"interfaces"`
}

func cmdDoctor(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	fix := fs.Bool("fix", false, "apply what this platform needs, where tp can do it itself")
	quiet := fs.Bool("quiet", false, "only print when something needs attention")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *fix {
		return doctorFix(ctx, *quiet)
	}
	fmt.Print(readBuildInfo())

	var h health
	if err := control(ctx, http.MethodGet, "/peers?wait=3s", nil, &h); err != nil {
		fmt.Println("daemon:      not answering:", err)
		return nil
	}

	fmt.Printf("daemon:      up %s\n", h.Uptime)
	fmt.Printf("interfaces:  %v\n", h.Interfaces)
	fmt.Printf("mdns in:     %d packets\n", h.Packets)

	// The daemon lists itself, so one peer means nobody else was heard.
	others := len(h.Peers) - 1
	fmt.Printf("peers:       %d\n", others)
	for _, p := range h.Peers[1:] {
		fmt.Printf("  %s  %s  %s\n", p.HostID, p.Hostname, p.Addr)
	}

	if runtime.GOOS == osDarwin {
		state := "not installed"
		if launchAgentInstalled() {
			state = launchAgentPath()
		}
		fmt.Printf("launch agent: %s\n", state)
	}
	if isWSL() {
		mode := "mirrored"
		if wslNAT(mustInterfaces()) {
			mode = "nat"
		}
		fmt.Printf("wsl:         %s networking\n", mode)
	}

	if h.Packets > 0 && others > 0 {
		fmt.Println("\nDiscovery is working.")
		return nil
	}
	if h.Packets > 0 {
		fmt.Println("\nMulticast is arriving but no other tp host has announced itself.")
		fmt.Println("Start tp on the other machine and run this again.")
		return nil
	}

	fmt.Println("\nNo multicast is arriving, so discovery cannot work.")
	for _, line := range discoveryAdvice() {
		fmt.Println(line)
	}
	return nil
}

// doctorFix does the part of the advice that is ours to do rather than yours.
// Only macOS has one: signing the daemon so the local network gate has an
// identity to record. Everything else is a Windows setting or a router.
func doctorFix(ctx context.Context, quiet bool) error {
	if runtime.GOOS != osDarwin {
		if !quiet {
			for _, line := range discoveryAdvice() {
				fmt.Println(line)
			}
		}
		return nil
	}
	return installAgent(ctx)
}

// installAgent gives the daemon an identity that the local network gate can
// record. The Go linker ad-hoc signs every binary with the identifier "a.out",
// so an unbundled tp is indistinguishable from every other Go program on the
// machine: nehelper logs "found bundle id a.out by PID", the preference cannot
// be stored against anything meaningful, and no prompt is ever shown. Copying
// the binary into a minimal app bundle and re-signing it with a real identifier
// is what makes the prompt appear and the toggle stick.
func installAgent(ctx context.Context) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	app, err := installBundle(ctx, self)
	if err != nil {
		return err
	}

	path := launchAgentPath()
	if path == "" {
		return errors.New("cannot find your home directory")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(agentPlist(app)), 0o600); err != nil {
		return err
	}

	// Replacing an older agent, so the previous one goes first and a failure
	// there is not fatal.
	//nolint:gosec // Every argument is a constant or a path we just built.
	_ = exec.CommandContext(ctx, "launchctl", "bootout", gui()+"/sh.tp.daemon").Run()
	_ = exec.CommandContext(ctx, "pkill", "-f", "tp daemon").Run()
	//nolint:gosec // Every argument is a constant or a path we just built.
	if out, err := exec.CommandContext(ctx, "launchctl", "bootstrap", gui(), path).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl bootstrap: %w: %s", err, out)
	}

	fmt.Printf("installed %s\n", path)
	fmt.Printf("daemon     %s\n", app)
	fmt.Println("macOS should now prompt: allow tp to find devices on local networks.")
	fmt.Println("If you miss it: System Settings, Privacy and Security, Local Network.")
	fmt.Println("Then run tp doctor.")
	return nil
}

// bundleID is the code signing identifier and the CFBundleIdentifier, and it is
// what shows up in Privacy and Security.
const bundleID = "sh.tp.daemon"

// installBundle writes ~/Library/Application Support/tp/tp.app around a copy of
// the binary and returns the executable inside it. A copy rather than a symlink
// because codesign signs what it is pointed at, and the signature has to travel
// with the file TCC sees.
func installBundle(ctx context.Context, bin string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	app := filepath.Join(home, "Library", "Application Support", "tp", "tp.app")
	macos := filepath.Join(app, "Contents", "MacOS")
	if err := os.MkdirAll(macos, 0o750); err != nil {
		return "", err
	}

	src, err := os.ReadFile(bin) //nolint:gosec // bin is os.Executable.
	if err != nil {
		return "", err
	}
	exe := filepath.Join(macos, "tp")
	// Written aside and renamed: the running daemon may be this very file, and
	// truncating a mapped executable kills it.
	tmp := exe + ".new"
	//nolint:gosec // 0o700 is owner only, and the daemon has to be executable.
	if err := os.WriteFile(tmp, src, 0o700); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, exe); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(infoPlist()), 0o600); err != nil {
		return "", err
	}

	if _, err := exec.LookPath("codesign"); err != nil {
		return exe, fmt.Errorf("codesign is not installed, so the daemon keeps the "+
			"identifier a.out and macOS cannot grant it local network access. "+
			"Install the Xcode command line tools and run tp install-agent again: %w", err)
	}
	//nolint:gosec // The identifier is a constant and app is a path we just built.
	out, err := exec.CommandContext(ctx, "codesign", "--force", "--sign", "-",
		"--identifier", bundleID, app).CombinedOutput()
	if err != nil {
		return exe, fmt.Errorf("codesign: %w: %s", err, out)
	}
	return exe, nil
}

func infoPlist() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>` + bundleID + `</string>
  <key>CFBundleName</key><string>tp</string>
  <key>CFBundleDisplayName</key><string>tp</string>
  <key>CFBundleExecutable</key><string>tp</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>LSBackgroundOnly</key><true/>
  <key>NSLocalNetworkUsageDescription</key>
  <string>tp finds other machines on this network so a paste can be fetched without a server.</string>
</dict>
</plist>
`
}

func gui() string { return fmt.Sprintf("gui/%d", os.Getuid()) }

func agentPlist(bin string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>sh.tp.daemon</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>daemon</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key>
  <dict><key>SuccessfulExit</key><false/></dict>
  <key>ProcessType</key><string>Background</string>
</dict>
</plist>
`, bin)
}
