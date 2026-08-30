package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// crockford is base32 without I, L, O and U, so a host ID reads aloud without
// ambiguity.
var crockford = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

const hostIDLen = 12

// loadIdentity returns this machine's long lived self signed certificate,
// generating the Ed25519 key on first run. Only the public key it carries is
// trusted. Subject, issuer and validity are ignored by both peers.
func loadIdentity() (tls.Certificate, error) {
	dir, err := dataDir()
	if err != nil {
		return tls.Certificate{}, err
	}
	priv, err := loadOrCreateKey(filepath.Join(dir, "identity.key"))
	if err != nil {
		return tls.Certificate{}, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tp"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Now().AddDate(100, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}, nil
}

func loadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	fi, err := os.Stat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return createKey(path)
	case err != nil:
		return nil, err
	}
	// Tightening the mode here would hide the fact that a readable key may
	// already have been copied.
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("%s: permissions are %04o, want 0600. Delete it to start over with a new identity", path, perm)
	}

	pemKey, err := os.ReadFile(path) //nolint:gosec // path is built from the user's own XDG directory.
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemKey)
	if block == nil {
		return nil, fmt.Errorf("%s: not a PEM key", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an Ed25519 key", path)
	}
	return priv, nil
}

func createKey(path string) (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemKey, 0o600); err != nil {
		return nil, err
	}
	return priv, nil
}

// hostID is Crockford base32 of SHA-256(SPKI) truncated to 12 characters. It
// names a machine in mDNS and in the pin cache, and never appears in a code.
func hostID(spki []byte) string {
	sum := sha256.Sum256(spki)
	return crockford.EncodeToString(sum[:])[:hostIDLen]
}
