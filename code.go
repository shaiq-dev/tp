package main

import (
	"crypto/rand"
	_ "embed"
	"fmt"
	"math/big"
	"strings"
)

const wordCount = 1295

//go:embed wordlist
var wordlistRaw string

var words []string

func init() {
	seen := make(map[string]bool, wordCount)
	for w := range strings.FieldsSeq(wordlistRaw) {
		if seen[w] {
			panic("wordlist: duplicate word " + w)
		}
		seen[w] = true
		words = append(words, w)
	}
	if len(words) != wordCount {
		panic(fmt.Sprintf("wordlist: got %d words, want %d", len(words), wordCount))
	}
}

// newCode draws three words independently and uniformly, giving 31.0 bits.
func newCode() string {
	parts := make([]string, 3)
	for i := range parts {
		parts[i] = words[randIndex(len(words))]
	}
	return strings.Join(parts, "-")
}

// newDigitCode backs --code-style=digits. Nine digits is 29.9 bits and survives
// dictation over a phone line, where words get misheard.
func newDigitCode() string {
	digits := make([]byte, 9)
	for i := range digits {
		digits[i] = byte('0' + randIndex(10)) //nolint:gosec // randIndex(10) is 0 to 9.
	}
	return groupDigits(string(digits))
}

func groupDigits(d string) string {
	return d[0:3] + "-" + d[3:6] + "-" + d[6:9]
}

// randIndex returns a uniform index in [0,n). crypto/rand.Int rejection samples
// internally, which matters because 1295 is not a power of two.
func randIndex(n int) int {
	if n <= 1 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return int(v.Int64())
}

// canonical turns typed input into the exact string the code was generated as,
// so both sides derive the same PAKE password. Words may be abbreviated to any
// prefix matching one entry, and digit codes may be grouped any way.
func canonical(code string) (string, error) {
	code = strings.ToLower(strings.TrimSpace(code))
	if digits, ok := digitCode(code); ok {
		return groupDigits(digits), nil
	}
	parts := strings.Split(code, "-")
	if len(parts) != 3 {
		return "", fmt.Errorf("a code is three words separated by -, got %q", code)
	}
	for i, p := range parts {
		w, err := expand(p)
		if err != nil {
			return "", err
		}
		parts[i] = w
	}
	return strings.Join(parts, "-"), nil
}

// digitCode reports whether code is a --code-style=digits code, returning its
// nine digits with the grouping stripped.
func digitCode(code string) (string, bool) {
	var digits strings.Builder
	for _, c := range code {
		switch {
		case c >= '0' && c <= '9':
			digits.WriteRune(c)
		case c == '-':
		default:
			return "", false
		}
	}
	if digits.Len() != 9 {
		return "", false
	}
	return digits.String(), true
}

// expand resolves one abbreviated word. An ambiguous prefix fails here, before
// anything reaches the network, so it costs no attempt against the rate limit.
func expand(prefix string) (string, error) {
	var match string
	n := 0
	for _, w := range words {
		if w == prefix {
			return w, nil
		}
		if strings.HasPrefix(w, prefix) {
			match, n = w, n+1
		}
	}
	switch n {
	case 0:
		return "", fmt.Errorf("%q is not in the wordlist", prefix)
	case 1:
		return match, nil
	default:
		return "", fmt.Errorf("%q is ambiguous, %d words match", prefix, n)
	}
}
