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

// Uninstall removes the current executable and tp's data and runtime
// directories.
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
		// macOS has no supported way to remove one Local Network permission
		// entry, tccutil does not expose this service.
		fmt.Println("The Local Network entry for tp stays in System Settings. Nothing removes")
		fmt.Println("one: the pane only toggles, and tccutil has no LocalNetwork service. It")
		fmt.Println("is inert now the binary is gone.")
	}
	return nil
}

// uninstallTargets returns every path removed by uninstall. Missing paths are
// safe to pass to RemoveAll.
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
	return out
}

func stopDaemon(ctx context.Context) {
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
