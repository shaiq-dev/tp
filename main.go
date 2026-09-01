package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Wait for initial mDNS replies. After peerWarmup, an empty cache
// returns immediately.
const discoveryWait = 2 * time.Second

const usage = `tp shares a paste with another machine on the same network.

  tp post [file]     read stdin or file, return a code
  tp get <code>      fetch a paste to stdout
  tp list            show the pastes this machine is serving
  tp del <code>      stop serving a paste

  tp doctor          explain why discovery is not finding other machines
  tp doctor --fix    apply what this platform needs, where tp can do it itself
  tp uninstall       remove the binary, the daemon and everything it stored

  tp completion <bash|zsh|fish>
  tp version
`

func main() {
	// Keep os.Exit outside app() so its deferred cleanup runs.
	os.Exit(app())
}

func app() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "tp:", err)
		return 1
	}
	return 0
}

type command struct {
	name   string
	hidden bool
	run    func(context.Context, []string) error
}

var commands = []command{
	{name: "post", run: cmdPost},
	{name: "get", run: cmdGet},
	{name: "list", run: func(ctx context.Context, _ []string) error { return cmdList(ctx) }},
	{name: "del", run: cmdDel},
	{name: "doctor", run: cmdDoctor},
	{name: "uninstall", run: cmdUninstall},
	{name: "completion", run: func(_ context.Context, args []string) error { return cmdCompletion(args) }},
	{name: "version", run: func(_ context.Context, _ []string) error {
		fmt.Print(readBuildInfo())
		return nil
	}},
	{name: "daemon", hidden: true, run: func(ctx context.Context, _ []string) error {
		if err := runDaemon(ctx); err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		return nil
	}},
}

func lookup(name string) (command, bool) {
	for _, c := range commands {
		if c.name == name {
			return c, true
		}
	}
	return command{}, false
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return errors.New("no command given")
	}
	cmd, ok := lookup(args[0])
	if !ok {
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", args[0])
	}
	return cmd.run(ctx, args[1:])
}
