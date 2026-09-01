package main

import (
	"errors"
	"testing"
)

func TestPinRoundTrip(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	if got, _ := readPins(); len(got) != 0 {
		t.Fatalf("a fresh cache holds %d pins", len(got))
	}
	first := pin{SPKI: "aaaa", Hostname: "laptop"}
	if err := savePin("HOST1", first); err != nil {
		t.Fatal(err)
	}
	if pins, _ := readPins(); pins["HOST1"] != first {
		t.Errorf("readPins = %+v, want %+v", pins["HOST1"], first)
	}

	// A replacement entry for the same host ID wins on the next read.
	second := pin{SPKI: "bbbb", Hostname: "laptop"}
	if err := savePin("HOST1", second); err != nil {
		t.Fatal(err)
	}
	if pins, _ := readPins(); pins["HOST1"] != second {
		t.Errorf("readPins = %+v, want %+v", pins["HOST1"], second)
	}
}

// A peer can advertise another machine's host ID. Treat a certificate that
// disagrees with that ID as a bad discovery result, not a key change warning.
func TestSpoofedHostIDIsNotAPinMismatch(t *testing.T) {
	d, addr := newTestDaemon(t)
	prs := addTestPaste(t, d, "acid-acorn-acre", "hello")

	tests := []struct {
		name    string
		hostID  string
		pin     *pin
		wantErr error
	}{
		{
			name:    "advertised host ID does not match the certificate",
			hostID:  "SPOOFED12345",
			pin:     &pin{SPKI: "not the right key"},
			wantErr: errNoMatch,
		},
		{
			name:    "the pinned host really did change its key",
			hostID:  d.hostID,
			pin:     &pin{SPKI: "not the right key"},
			wantErr: new(pinMismatchError),
		},
		{
			name:   "no pin yet",
			hostID: d.hostID,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := candidate{hostID: tt.hostID, addr: addr, pin: tt.pin}
			body, err := fetch(t.Context(), prs, []candidate{c})
			switch {
			case tt.wantErr == nil:
				if err != nil || string(body) != "hello" {
					t.Fatalf("fetch = %q, %v", body, err)
				}
			case errors.Is(tt.wantErr, errNoMatch):
				if !errors.Is(err, errNoMatch) {
					t.Fatalf("fetch error = %v, want errNoMatch", err)
				}
			default:
				if _, ok := errors.AsType[*pinMismatchError](err); !ok {
					t.Fatalf("fetch error = %v, want a pin mismatch", err)
				}
			}
		})
	}
}
