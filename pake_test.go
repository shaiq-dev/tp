package main

import (
	"bytes"
	"crypto/sha512"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/gtank/ristretto255"
)

// CPace reference vector for G_Coffee25519 (ristretto255) with SHA-512, copied
// verbatim from cfrg/draft-irtf-cfrg-cpace testvectors.json.
//
//go:embed testdata/cpace_ristretto255.json
var cpaceVectorJSON []byte

func cpaceVector(t *testing.T) map[string][]byte {
	t.Helper()
	var raw map[string]string
	if err := json.Unmarshal(cpaceVectorJSON, &raw); err != nil {
		t.Fatal(err)
	}
	out := make(map[string][]byte, len(raw))
	for k, v := range raw {
		b, err := hex.DecodeString(v)
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		out[k] = b
	}
	return out
}

func mustScalar(t *testing.T, b []byte) *ristretto255.Scalar {
	t.Helper()
	s, err := ristretto255.NewScalar().SetCanonicalBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCPaceReferenceVector(t *testing.T) {
	v := cpaceVector(t)
	g := calculateGenerator(v["PRS"], v["CI"], v["sid"])
	ya, yb := mustScalar(t, v["ya"]), mustScalar(t, v["yb"])

	kFromYa, err := scalarMultVfy(ya, v["Yb"])
	if err != nil {
		t.Fatal(err)
	}
	kFromYb, err := scalarMultVfy(yb, v["Ya"])
	if err != nil {
		t.Fatal(err)
	}

	// The reference vector includes associated data, while tp does not. Build
	// the transcript here because sessionKey handles only empty AD.
	transcript := oCat(lvCat(v["Ya"], v["ADa"]), lvCat(v["Yb"], v["ADb"]))
	iskInput := append(lvCat([]byte(cpaceDSIISK), v["sid"], v["K"]), transcript...)
	iskSum := sha512.Sum512(iskInput)

	tests := []struct {
		name string
		got  []byte
		want []byte
	}{
		{"generator", g.Bytes(), v["g"]},
		{"Ya", ristretto255.NewIdentityElement().ScalarMult(ya, g).Bytes(), v["Ya"]},
		{"Yb", ristretto255.NewIdentityElement().ScalarMult(yb, g).Bytes(), v["Yb"]},
		{"K from ya", kFromYa, v["K"]},
		{"K from yb", kFromYb, v["K"]},
		{"ISK_SY", iskSum[:], v["ISK_SY"]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !bytes.Equal(tt.got, tt.want) {
				t.Errorf("\n got  %x\n want %x", tt.got, tt.want)
			}
		})
	}
}

func TestPrependLen(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{"empty", nil, "00"},
		{"short", []byte("1234"), "0431323334"},
		{"one byte boundary", bytes.Repeat([]byte{0xaa}, 127), "7f" + hex.EncodeToString(bytes.Repeat([]byte{0xaa}, 127))},
		{"two byte length", bytes.Repeat([]byte{0xaa}, 128), "8001" + hex.EncodeToString(bytes.Repeat([]byte{0xaa}, 128))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hex.EncodeToString(prependLen(tt.in)); got != tt.want {
				t.Errorf("prependLen = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestOCatIsOrderIndependent(t *testing.T) {
	tests := []struct{ a, b string }{
		{"aaaa", "bbbb"},
		{"bbbb", "aaaa"},
		{"a", "aa"},
		{"", "a"},
	}
	for _, tt := range tests {
		t.Run(tt.a+"/"+tt.b, func(t *testing.T) {
			a, b := []byte(tt.a), []byte(tt.b)
			if !bytes.Equal(oCat(a, b), oCat(b, a)) {
				t.Errorf("oCat(%q,%q) != oCat(%q,%q)", tt.a, tt.b, tt.b, tt.a)
			}
		})
	}
}

func TestScalarMultVfyRejectsBadPoints(t *testing.T) {
	tests := []struct {
		name  string
		point []byte
	}{
		{"identity", make([]byte, pointLen)},
		{"too short", make([]byte, pointLen-1)},
		{"too long", make([]byte, pointLen+1)},
		{"non canonical", bytes.Repeat([]byte{0xff}, pointLen)},
	}
	s := randomScalar()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := scalarMultVfy(s, tt.point); err == nil {
				t.Errorf("accepted %x", tt.point)
			}
		})
	}
}

// Matching passwords must produce the same confirmation tag, different
// passwords must not.
func TestPakeConfirmation(t *testing.T) {
	right, err := derivePRS("acid-acorn-acre")
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := derivePRS("acid-acorn-adobe")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		a, b      []byte
		wantMatch bool
	}{
		{"same password", right, right, true},
		{"different password", right, wrong, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sid, ci := []byte("channel binding"), channelID("HOST12345678")
			sideA := newPakeSide(tt.a, ci, sid)
			sideB := newPakeSide(tt.b, ci, sid)
			if err := sideA.finish(sideB.share, sid); err != nil {
				t.Fatal(err)
			}
			if err := sideB.finish(sideA.share, sid); err != nil {
				t.Fatal(err)
			}
			if got := macEqual(sideA.clientTag(), sideB.clientTag()); got != tt.wantMatch {
				t.Errorf("confirmation matched = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

// Channel binding must prevent a confirmation tag from being reused across TLS
// connections.
func TestChannelBindingSeparatesSessions(t *testing.T) {
	prs, err := derivePRS("acid-acorn-acre")
	if err != nil {
		t.Fatal(err)
	}
	ci := channelID("HOST12345678")
	a := newPakeSide(prs, ci, []byte("exporter one"))
	b := newPakeSide(prs, ci, []byte("exporter two"))
	if err := a.finish(b.share, []byte("exporter one")); err != nil {
		t.Fatal(err)
	}
	if err := b.finish(a.share, []byte("exporter two")); err != nil {
		t.Fatal(err)
	}
	if macEqual(a.clientTag(), b.clientTag()) {
		t.Error("two connections produced the same confirmation tag")
	}
}
