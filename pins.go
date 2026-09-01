package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// A pin records the SPKI after a PAKE authenticated fetch. Later fetches
// prioritize that host and detect unexpected key changes.
type pin struct {
	SPKI     string
	Hostname string
}

func knownHostsPath() (string, error) {
	dir, err := dataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "known_hosts"), nil
}

func spkiHash(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.RawStdEncoding.EncodeToString(sum[:])
}

// readPins returns the physical line count so savePin knows when duplicate
// history needs compaction.
func readPins() (map[string]pin, int) {
	pins := make(map[string]pin)
	path, err := knownHostsPath()
	if err != nil {
		return pins, 0
	}
	b, err := os.ReadFile(path) //nolint:gosec // path is within the user's XDG data directory.
	if err != nil {
		return pins, 0
	}
	lines := 0
	for line := range strings.Lines(string(b)) {
		lines++
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		p := pin{SPKI: fields[1]}
		if len(fields) > 2 {
			p.Hostname = fields[2]
		}
		// Appends may duplicate host IDs, the newest entry wins.
		pins[fields[0]] = p
	}
	return pins, lines
}

// savePin appends updates to avoid lost writes between concurrent fetches. Duplicates
// are resolved on read and compacted once stale history outweighs live entries.
func savePin(hostID string, p pin) error {
	pins, lines := readPins()
	if old, ok := pins[hostID]; ok && old == p {
		return nil
	}
	path, err := knownHostsPath()
	if err != nil {
		return err
	}
	pins[hostID] = p
	if lines >= 2*len(pins) {
		return writePins(path, pins)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) //nolint:gosec // path is within the user's XDG data directory.
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f, "%s %s %s\n", hostID, p.SPKI, p.Hostname); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func writePins(path string, pins map[string]pin) error {
	var b strings.Builder
	for id, p := range pins {
		fmt.Fprintf(&b, "%s %s %s\n", id, p.SPKI, p.Hostname)
	}
	// Use a unique temporary file so concurrent compactions never share partial
	// output.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".known_hosts-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(b.String()); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
