package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Uninstalling is more than deleting a binary now: the macOS fix leaves a launch
// agent and a signed bundle behind, and pastes and pins live under XDG. Listing
// those paths in a README is how one gets missed.
func cmdUninstall(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	yes := fs.Bool("yes", false, "do not ask")
	if err := fs.Parse(args); err != nil {
		return err
	}

	targets := uninstallTargets()
	fmt.Println("This removes:")
	for _, t := range targets {
		fmt.Println("  " + t)
	}
	if !*yes && !confirmRemoval() {
		return nil
	}

	stopDaemon(ctx)
	for _, t := range targets {
		if err := os.RemoveAll(t); err != nil {
			fmt.Fprintf(os.Stderr, "tp: could not remove %s: %v\n", t, err)
		}
	}

	fmt.Println("done")
	if runtime.GOOS == osDarwin {
		// Nothing removes a single entry. tccutil has no LocalNetwork service at
		// all: tccd answers "Service name is invalid on this platform". The pane
		// only toggles, and the store is a keyed archive nehelper holds open.
		fmt.Println("The Local Network entry for tp stays in System Settings. Nothing removes")
		fmt.Println("one: the pane only toggles, and tccutil has no LocalNetwork service. It")
		fmt.Println("is inert now the binary is gone.")
	}
	return nil
}

// uninstallTargets is every path tp creates, in the order they are safe to
// remove. Paths that do not exist are harmless to include.
func uninstallTargets() []string {
	var out []string
	if self, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(self); err == nil {
			self = resolved
		}
		out = append(out, self)
	}
	if data, err := xdgPath("XDG_DATA_HOME", ".local", "share"); err == nil {
		out = append(out, data)
	}
	if state, err := xdgPath("XDG_RUNTIME_DIR", ".local", "state"); err == nil {
		out = append(out, state)
	}
	if runtime.GOOS == osDarwin {
		if p := launchAgentPath(); p != "" {
			out = append(out, p)
		}
		if home, err := os.UserHomeDir(); err == nil {
			out = append(out, filepath.Join(home, "Library", "Application Support", "tp"))
		}
	}
	return out
}

func stopDaemon(ctx context.Context) {
	if runtime.GOOS == osDarwin {
		//nolint:gosec // Both arguments are constants.
		_ = exec.CommandContext(ctx, "launchctl", "bootout", gui()+"/sh.tp.daemon").Run()
	}
	_ = exec.CommandContext(ctx, "pkill", "-f", "tp daemon").Run()
}

func confirmRemoval() bool {
	fmt.Print("Continue? [y/N] ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}
