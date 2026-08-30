package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"errors"

	"github.com/gtank/ristretto255"
	"golang.org/x/crypto/scrypt"
)

// CPace over ristretto255 with SHA-512, following draft-irtf-cfrg-cpace, which
// calls this group G_Coffee25519 in its test vector file. Roles are symmetric,
// so the session key transcript uses the unordered o_cat concatenation.
const (
	cpaceDSI    = "CPaceRistretto255"
	cpaceDSIISK = "CPaceRistretto255_ISK"

	// cpaceBlock is the SHA-512 input block size, s_in_bytes in the draft.
	cpaceBlock = 128
)

// scrypt turns a spoken code into the PAKE password. These parameters set what
// each guess costs an attacker: 32 MiB and roughly 37 ms per candidate.
const (
	scryptN   = 1 << 15
	scryptR   = 8
	scryptP   = 1
	scryptLen = 32
)

var scryptSalt = []byte("tp/pake/v1")

var errBadPoint = errors.New("pake: peer sent an invalid or identity element")

func derivePRS(code string) ([]byte, error) {
	return scrypt.Key([]byte(code), scryptSalt, scryptN, scryptR, scryptP, scryptLen)
}

// prependLen is the draft's LEB128 length prefix.
func prependLen(b []byte) []byte {
	n := len(b)
	var out []byte
	for {
		if n < 128 {
			out = append(out, byte(n))
		} else {
			out = append(out, byte(n&0x7f)+0x80)
		}
		n >>= 7
		if n == 0 {
			break
		}
	}
	return append(out, b...)
}

func lvCat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, prependLen(p)...)
	}
	return out
}

// oCat orders its inputs by content, so both sides agree without either knowing
// which spoke first.
func oCat(a, b []byte) []byte {
	out := []byte("oc")
	if lexGreater(a, b) {
		return append(append(out, a...), b...)
	}
	return append(append(out, b...), a...)
}

func lexGreater(a, b []byte) bool {
	for i := range min(len(a), len(b)) {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return len(a) > len(b)
}

// calculateGenerator maps the password, channel identifier and session id to a
// group element. Everything an offline attacker needs sits inside this hash, and
// getting back out of it means solving a discrete log.
func calculateGenerator(prs, ci, sid []byte) *ristretto255.Element {
	zpad := max(0, cpaceBlock-1-len(prependLen(prs))-len(prependLen([]byte(cpaceDSI))))
	sum := sha512.Sum512(lvCat([]byte(cpaceDSI), prs, make([]byte, zpad), ci, sid))
	g, err := ristretto255.NewIdentityElement().SetUniformBytes(sum[:])
	if err != nil {
		panic("ristretto255 rejected a 64 byte uniform input: " + err.Error())
	}
	return g
}

func randomScalar() *ristretto255.Scalar {
	var b [64]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	s, err := ristretto255.NewScalar().SetUniformBytes(b[:])
	if err != nil {
		panic("ristretto255 rejected a 64 byte uniform input: " + err.Error())
	}
	return s
}

// scalarMultVfy rejects non canonical encodings and the identity element. The
// draft requires an abort on both, since either collapses the shared secret to
// a value the peer can predict.
func scalarMultVfy(s *ristretto255.Scalar, encoded []byte) ([]byte, error) {
	if len(encoded) != pointLen {
		return nil, errBadPoint
	}
	p, err := ristretto255.NewIdentityElement().SetCanonicalBytes(encoded)
	if err != nil {
		return nil, errBadPoint
	}
	k := ristretto255.NewIdentityElement().ScalarMult(s, p)
	if k.Equal(ristretto255.NewIdentityElement()) == 1 {
		return nil, errBadPoint
	}
	return k.Bytes(), nil
}

// sessionKey derives the CPace intermediate session key from the shared secret
// and both public shares.
func sessionKey(sid, k, ya, yb []byte) []byte {
	transcript := oCat(lvCat(ya, nil), lvCat(yb, nil))
	sum := sha512.Sum512(append(lvCat([]byte(cpaceDSIISK), sid, k), transcript...))
	return sum[:]
}

// confirm is the key confirmation tag. Confirmation turns a shared secret into
// authentication, and CPace without it proves nothing.
func confirm(sk []byte, label string) []byte {
	m := hmac.New(sha256.New, sk)
	m.Write([]byte(label))
	return m.Sum(nil)
}

func macEqual(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }
