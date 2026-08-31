package main

import (
	"crypto/cipher"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/gtank/ristretto255"
	"golang.org/x/crypto/chacha20poly1305"
)

// The data plane uses four length prefixed messages over TLS 1.3. A balanced
// PAKE needs two round trips before releasing the payload, so it does not fit
// into a single HTTP request and response.
//
//  1. client to server   version || Ya
//  2. server to client   n || n*(Yb_i || MACs_i)
//  3. client to server   MACc
//  4. server to client   payload
//
// The server cannot tell which paste a code belongs to, so it runs one CPace
// instance per candidate and returns every server confirmation. The client
// selects the one that verifies. With a wrong code, matching the server's secret
// would require the discrete log of Ya under the correct password derived
// generator, so no confirmation verifies.
const (
	wireVersion = 1
	pointLen    = 32
	macLen      = 32

	// Negotiate the wire protocol during TLS so incompatible peers fail before
	// starting an exchange. A future client can offer "tp/2" first and fall back
	// to this version.
	alpnProto = "tp/1"

	aeadOverhead = chacha20poly1305.Overhead

	helloLen = 1 + pointLen
	maxFrame = maxPasteSize + 64*1024
)

// The largest offer contains one public point and confirmation tag per
// candidate, plus its candidate count.
const maxOfferLen = 2 + maxCandidates*(pointLen+macLen)

var (
	errProtocol = errors.New("protocol error")
	errNoMatch  = errors.New("no paste for that code on this host")
)

// Bind the PAKE transcript to the TLS exporter so messages from one connection
// cannot be relayed into another.
func channelBinding(c *tls.Conn) ([]byte, error) {
	state := c.ConnectionState()
	return state.ExportKeyingMaterial("tp/cb/v1", nil, 32)
}

// channelID is the CPace CI input derived from the protocol version and the host
// identity committed to by the certificate key.
func channelID(serverHostID string) []byte {
	return lvCat([]byte("tp/v1"), []byte(serverHostID))
}

func writeFrame(w io.Writer, b []byte) error {
	if len(b) > maxFrame {
		return fmt.Errorf("%w: frame of %d bytes exceeds the %d byte limit", errProtocol, len(b), maxFrame)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b))) //nolint:gosec // Bounded by the maxFrame check above.
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

// Validate the advertised length before allocating. Handshake callers use
// tighter limits, only the payload reader permits maxFrame.
func readFrame(r io.Reader, limit uint32) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > limit {
		return nil, fmt.Errorf("%w: frame of %d bytes exceeds the %d byte limit", errProtocol, n, limit)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

// pakeSide represents one server candidate or the client's single code.
type pakeSide struct {
	scalar *ristretto255.Scalar
	share  []byte
	sk     []byte
}

func newPakeSide(prs, ci, sid []byte) *pakeSide {
	g := calculateGenerator(prs, ci, sid)
	y := randomScalar()
	return &pakeSide{
		scalar: y,
		share:  ristretto255.NewIdentityElement().ScalarMult(y, g).Bytes(),
	}
}

// finish validates the peer's share and derives the intermediate session key.
func (p *pakeSide) finish(peerShare, sid []byte) error {
	k, err := scalarMultVfy(p.scalar, peerShare)
	if err != nil {
		return err
	}
	p.sk = sessionKey(sid, k, p.share, peerShare)
	return nil
}

func (p *pakeSide) serverTag() []byte { return confirm(p.sk, "tp/confirm/server") }
func (p *pakeSide) clientTag() []byte { return confirm(p.sk, "tp/confirm/client") }

// seal adds application layer encryption under a key derived from the PAKE
// session. This is independent of TLS record encryption, so a compromise of
// that layer alone still exposes only the inner ciphertext.
//
// The zero nonce is safe because each derived key encrypts exactly one payload.
// The session key is unique to its TLS connection through the channel binding.
//
// The caller provides room for the AEAD tag, allowing Seal to reuse the payload
// buffer. Avoiding a second full size copy matters at the paste and connection
// limits, where those allocations can total hundreds of megabytes.
func (p *pakeSide) seal(body []byte) ([]byte, error) {
	aead, err := p.aead()
	if err != nil {
		return nil, err
	}
	return aead.Seal(body[:0], make([]byte, aead.NonceSize()), body, nil), nil
}

func (p *pakeSide) open(sealed []byte) ([]byte, error) {
	aead, err := p.aead()
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, make([]byte, aead.NonceSize()), sealed, nil)
}

func (p *pakeSide) aead() (cipher.AEAD, error) {
	return chacha20poly1305.New(confirm(p.sk, "tp/payload/v1"))
}
