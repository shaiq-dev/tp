package main

import (
	"errors"
	"testing"
)

func TestPinRoundTrip(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	if got := loadPins(); len(got) != 0 {
		t.Fatalf("a fresh cache holds %d pins", len(got))
	}
	first := pin{SPKI: "aaaa", Hostname: "laptop"}
	if err := savePin("HOST1", first); err != nil {
		t.Fatal(err)
	}
	if got := loadPins()["HOST1"]; got != first {
		t.Errorf("loadPins = %+v, want %+v", got, first)
	}

	// A rotated key appends a line, and the newer one wins on read.
	second := pin{SPKI: "bbbb", Hostname: "laptop"}
	if err := savePin("HOST1", second); err != nil {
		t.Fatal(err)
	}
	if got := loadPins()["HOST1"]; got != second {
		t.Errorf("loadPins = %+v, want %+v", got, second)
	}
}

// Anyone on the LAN can advertise someone else's host ID. That has to drop the
// candidate quietly, since a pin mismatch tells the user their peer's key
// changed.
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
