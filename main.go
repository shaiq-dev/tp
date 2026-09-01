package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
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

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return errors.New("no command given")
	}
	switch cmd, rest := args[0], args[1:]; cmd {
	case "post":
		return cmdPost(ctx, rest)
	case "get":
		return cmdGet(ctx, rest)
	case "list":
		return cmdList(ctx)
	case "del":
		return cmdDel(ctx, rest)
	case "doctor":
		return cmdDoctor(ctx, rest)
	case "uninstall":
		return cmdUninstall(ctx, rest)
	case "completion":
		return cmdCompletion(rest)
	case "version":
		fmt.Print(readBuildInfo())
		return nil
	case "daemon":
		if err := runDaemon(ctx); err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		return nil
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func cmdPost(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("post", flag.ExitOnError)
	label := fs.String("label", "", "label shown in tp list")
	ttl := fs.Duration("ttl", 0, "time to live, default 1h and at most 24h")
	maxGets := fs.Int("max-gets", 0, "drop the paste after N fetches")
	burn := fs.Bool("burn", false, "shorthand for --max-gets 1")
	style := fs.String("code-style", "words", "words or digits")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *style != "words" && *style != "digits" {
		return errors.New("--code-style must be words or digits")
	}
	if *burn {
		*maxGets = 1
	}

	body := io.Reader(os.Stdin)
	if name := fs.Arg(0); name != "" {
		f, err := os.Open(name) //nolint:gosec // The path is the argument the user typed.
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		body = f
	}

	q := url.Values{"code_style": {*style}}
	if *label != "" {
		q.Set("label", *label)
	}
	if *ttl != 0 {
		q.Set("ttl", ttl.String())
	}
	if *maxGets != 0 {
		q.Set("max_gets", strconv.Itoa(*maxGets))
	}

	var out struct {
		Code string `json:"code"`
	}
	if err := control(ctx, http.MethodPost, "/pastes?"+q.Encode(), body, &out); err != nil {
		return err
	}
	fmt.Println(out.Code)
	return nil
}

func cmdGet(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("get", flag.ExitOnError)
	host := fs.String("host", "", "skip discovery and fetch from this host[:port]")
	timeout := fs.Duration("timeout", 20*time.Second, "give up after this long")
	if err := fs.Parse(args); err != nil {
		return err
	}

	code, err := canonical(fs.Arg(0))
	if err != nil {
		return err
	}
	// Derive once, every candidate exchange uses the same PAKE secret.
	prs, err := derivePRS(code)
	if err != nil {
		return err
	}

	var cands []candidate
	if *host != "" {
		cands = []candidate{{addr: withDefaultPort(*host)}}
	} else if cands, err = discover(ctx); err != nil {
		return err
	}
	if len(cands) == 0 {
		return errors.New("no tp hosts found on this network, try tp get --host <addr>")
	}

	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	body, err := fetch(ctx, prs, cands)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(body)
	return err
}

func withDefaultPort(host string) string {
	if _, _, err := net.SplitHostPort(host); err != nil {
		return net.JoinHostPort(host, strconv.Itoa(dataPort))
	}
	return host
}

// discover reads the daemon's mDNS cache, waiting briefly during cold start.
func discover(ctx context.Context) ([]candidate, error) {
	var out struct {
		Peers      []peer `json:"peers"`
		Diagnostic string `json:"diagnostic"`
	}
	// A daemon forked by this command may not have received an announcement yet.
	if err := control(ctx, http.MethodGet, "/peers?wait="+discoveryWait.String(), nil, &out); err != nil {
		return nil, err
	}
	if out.Diagnostic != "" {
		fmt.Fprintln(os.Stderr, "tp:", out.Diagnostic)
	}

	pins := loadPins()
	cands := make([]candidate, 0, len(out.Peers))
	for _, p := range out.Peers {
		c := candidate{hostID: p.HostID, hostname: p.Hostname, addr: p.Addr}
		if pinned, ok := pins[p.HostID]; ok {
			c.pin = &pinned
		}
		cands = append(cands, c)
	}
	return cands, nil
}

func cmdList(ctx context.Context) error {
	var out struct {
		HostID string   `json:"host_id"`
		Port   int      `json:"port"`
		Pastes []*paste `json:"pastes"`
	}
	if err := control(ctx, http.MethodGet, "/pastes", nil, &out); err != nil {
		return err
	}
	fmt.Printf("host %s, serving on port %d\n", out.HostID, out.Port)
	if len(out.Pastes) == 0 {
		fmt.Println("no pastes")
		return nil
	}
	for _, p := range out.Pastes {
		state := fmt.Sprintf("%d gets", p.Gets)
		if p.MaxGets > 0 {
			state = fmt.Sprintf("%d/%d gets", p.Gets, p.MaxGets)
		}
		if p.Burned {
			state += ", burned"
		}
		fmt.Printf("%8d B  expires in %-9s  %-16s %s\n",
			p.Size, time.Until(p.ExpiresAt).Round(time.Second), state, p.Label)
	}
	return nil
}

func cmdDel(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("del", flag.ExitOnError)
	all := fs.Bool("all", false, "drop every paste")
	if err := fs.Parse(args); err != nil {
		return err
	}

	path := "/pastes"
	if !*all {
		if fs.Arg(0) == "" {
			return errors.New("give a code or --all")
		}
		code, err := canonical(fs.Arg(0))
		if err != nil {
			return err
		}
		// Send the derived PAKE secret, not the user facing code.
		prs, err := derivePRS(code)
		if err != nil {
			return err
		}
		path += "/" + hex.EncodeToString(prs)
	}
	return control(ctx, http.MethodDelete, path, nil, nil)
}

// control starts the daemon if needed, sends a request over its Unix socket and
// decodes the response into out.
func control(ctx context.Context, method, path string, body io.Reader, out any) error {
	sock, err := sockPath()
	if err != nil {
		return err
	}
	if err := ensureDaemon(ctx, sock); err != nil {
		return err
	}
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sock)
			},
		},
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://tp"+path, body)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	return decodeControlResponse(resp, out)
}

func decodeControlResponse(resp *http.Response, out any) error {
	if resp.StatusCode >= http.StatusBadRequest {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s", strings.TrimSpace(string(msg)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// ensureDaemon starts the daemon on demand, avoiding a required service manager.
func ensureDaemon(ctx context.Context, sock string) error {
	if dialSock(ctx, sock) {
		return nil
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	// Do not bind the daemon to the caller's context, it must survive this
	// command.
	//
	//nolint:gosec,noctx // self is os.Executable, the child intentionally outlives ctx.
	cmd := exec.Command(self, "daemon")
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()

	return waitForSock(ctx, sock)
}

func waitForSock(ctx context.Context, sock string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		if dialSock(ctx, sock) {
			return nil
		}
		select {
		case <-time.After(20 * time.Millisecond):
		case <-ctx.Done():
			return fmt.Errorf("daemon did not come up at %s", sock)
		}
	}
}

func dialSock(ctx context.Context, sock string) bool {
	c, err := new(net.Dialer).DialContext(ctx, "unix", sock)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}
