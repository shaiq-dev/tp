package main

import "testing"

func TestWordlist(t *testing.T) {
	if len(words) != wordCount {
		t.Fatalf("len(words) = %d, want %d", len(words), wordCount)
	}
	// Only holds because no word is a strict prefix of another.
	for _, w := range words {
		got, err := expand(w)
		if err != nil || got != w {
			t.Fatalf("expand(%q) = %q, %v", w, got, err)
		}
	}
}

func TestExpand(t *testing.T) {
	tests := []struct {
		name    string
		prefix  string
		want    string
		wantErr bool
	}{
		{"exact word", "acid", "acid", false},
		{"unique prefix", "aci", "acid", false},
		{"ambiguous prefix", "boot", "", true},
		{"not a word", "zzz", "", true},
		{"empty", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := expand(tt.prefix)
			if (err != nil) != tt.wantErr {
				t.Fatalf("expand(%q) error = %v, wantErr %v", tt.prefix, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("expand(%q) = %q, want %q", tt.prefix, got, tt.want)
			}
		})
	}
}

func TestCanonical(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"full words", "acid-acorn-acre", "acid-acorn-acre", false},
		{"abbreviated", "aci-aco-acr", "acid-acorn-acre", false},
		{"uppercase and spaces", "  ACID-ACORN-ACRE ", "acid-acorn-acre", false},
		{"two words", "acid-acorn", "", true},
		{"four words", "acid-acorn-acre-atom", "", true},
		{"ambiguous word", "boot-acorn-acre", "", true},
		{"digits", "015-848-720", "015-848-720", false},
		{"digits regrouped", "01-5848-720", "015-848-720", false},
		{"digits unseparated", "015848720", "015-848-720", false},
		{"eight digits", "015-848-72", "", true},
		{"digits mixed with letters", "015-848-72a", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := canonical(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("canonical(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("canonical(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// Codes printed by tp must round trip through the input parser unchanged.
func TestGeneratedCodesAreCanonical(t *testing.T) {
	for _, gen := range []struct {
		name string
		fn   func() string
	}{
		{"words", newCode},
		{"digits", newDigitCode},
	} {
		t.Run(gen.name, func(t *testing.T) {
			for range 200 {
				code := gen.fn()
				got, err := canonical(code)
				if err != nil || got != code {
					t.Fatalf("canonical(%q) = %q, %v", code, got, err)
				}
			}
		})
	}
}
