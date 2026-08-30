package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadIdentityIsStable(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	first, err := loadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	// The certificate is regenerated on every start, so the host ID has to come
	// from the key rather than the certificate, or every pin breaks on restart.
	if a, b := hostID(first.Leaf.RawSubjectPublicKeyInfo), hostID(second.Leaf.RawSubjectPublicKeyInfo); a != b {
		t.Errorf("host ID changed across loads: %s then %s", a, b)
	}
}

func TestLoadIdentityRefusesAReadableKey(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dir)
	if _, err := loadIdentity(); err != nil {
		t.Fatal(err)
	}

	key := filepath.Join(dir, "tp", "identity.key")
	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadIdentity(); err == nil {
		t.Error("loadIdentity accepted a world readable private key")
	}
}

func TestHostIDLength(t *testing.T) {
	id := hostID([]byte("some subject public key info"))
	if len(id) != hostIDLen {
		t.Errorf("hostID length = %d, want %d", len(id), hostIDLen)
	}
	if strings.ContainsAny(id, "ILOU") {
		t.Errorf("host ID %q contains a character Crockford base32 excludes", id)
	}
}
