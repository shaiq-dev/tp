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

// A pin lets a later fetch try one host first and check its certificate
// directly, skipping the fan out. A mismatch aborts rather than falling back.
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

func loadPins() map[string]pin {
	pins, _ := readPins()
	return pins
}

// readPins also reports the line count, which savePin uses to decide when
// appended history outweighs the entries.
func readPins() (map[string]pin, int) {
	pins := make(map[string]pin)
	path, err := knownHostsPath()
	if err != nil {
		return pins, 0
	}
	b, err := os.ReadFile(path) //nolint:gosec // path is built from the user's own XDG directory.
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
		// Later lines win, resolving the duplicates that appending leaves.
		pins[fields[0]] = p
	}
	return pins, lines
}

// savePin appends rather than rewriting, so two fetches running at once cannot
// drop each other's entries. Duplicates resolve on read and the file is
// compacted once history outweighs entries.
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

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) //nolint:gosec // path is built from the user's own XDG directory.
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
	// A fixed temp name would collide with another tp running concurrently,
	// leaving each to read the other's half written file.
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
