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

// https://en.wikipedia.org/wiki/Password-authenticated_key_agreement
//
// CPace over ristretto255 and SHA-512, following draft-irtf-cfrg-cpace. The
// draft's test vectors call this group G_Coffee25519. Because the roles are
// symmetric, the session transcript uses the role independent o_cat ordering.
const (
	cpaceDSI    = "CPaceRistretto255"
	cpaceDSIISK = "CPaceRistretto255_ISK"

	// SHA-512 block size, named s_in_bytes in the draft.
	cpaceBlock = 128
)

// These scrypt parameters make each code guess memory hard, using roughly
// 32 MiB per derivation.
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

// prependLen applies the draft's LEB128 length encoding.
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

// oCat provides the role independent ordering used by the symmetric transcript.
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

// calculateGenerator maps the password and channel/session identifiers to a
// Ristretto group element.
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

// scalarMultVfy rejects non canonical points and the identity element, either of
// which would make the shared secret predictable.
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

// sessionKey derives the CPace intermediate key from the shared point, session
// ID and role independent public share transcript.
func sessionKey(sid, k, ya, yb []byte) []byte {
	transcript := oCat(lvCat(ya, nil), lvCat(yb, nil))
	sum := sha512.Sum512(append(lvCat([]byte(cpaceDSIISK), sid, k), transcript...))
	return sum[:]
}

// confirm binds a role label to the session key. Explicit key confirmation is
// what authenticates the peer.
func confirm(sk []byte, label string) []byte {
	m := hmac.New(sha256.New, sk)
	m.Write([]byte(label))
	return m.Sum(nil)
}

func macEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
