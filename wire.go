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

// The data plane speaks a four message framed exchange over TLS 1.3 rather than
// HTTP. A balanced PAKE needs two round trips before any payload can be
// released, and one HTTP request and response is one round trip.
//
//  1. client to server   version || Ya
//  2. server to client   n || n*(Yb_i || MACs_i)
//  3. client to server   MACc
//  4. server to client   payload
//
// The server does not know which of its pastes a code belongs to, so it runs one
// CPace instance per paste and answers for all of them. The client finds its own
// by which server confirmation verifies. A wrong code verifies none: computing
// any K_i needs the discrete log of Ya under that paste's generator, which only
// the right password produces.
const (
	wireVersion = 1
	pointLen    = 32
	macLen      = 32

	// alpnProto names the protocol inside the TLS handshake, so an unsupported
	// peer fails there rather than halfway through an exchange. A later client
	// offers "tp/2" first and falls back to this.
	alpnProto = "tp/1"

	aeadOverhead = chacha20poly1305.Overhead

	helloLen = 1 + pointLen
	maxFrame = maxPasteSize + 64*1024
)

// maxOfferLen bounds the largest handshake frame: one point and one tag for
// every candidate the server offers.
const maxOfferLen = 2 + maxCandidates*(pointLen+macLen)

var (
	errProtocol = errors.New("protocol error")
	errNoMatch  = errors.New("no paste for that code on this host")
)

// channelBinding ties the PAKE transcript to this exact TLS connection. Two
// connections have different exporter values, so an exchange cannot be relayed
// from one into another.
func channelBinding(c *tls.Conn) ([]byte, error) {
	state := c.ConnectionState()
	return state.ExportKeyingMaterial("tp/cb/v1", nil, 32)
}

// channelID is the CPace CI input. Both sides derive it from the protocol
// version and the host ID the certificate commits to.
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

// readFrame bounds the allocation a peer can provoke. Handshake frames are tens
// of bytes, so only the payload read passes maxFrame.
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

// pakeSide is one CPace instance, meaning one paste on the server or the single
// code the client holds.
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

// finish completes the exchange against the peer's share and sets sk.
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

// seal encrypts the paste under a key derived from the session key, on top of
// the TLS already covering it. TLS is a large piece of code with a steady supply
// of advisories, and a break in one exposes ciphertext this way rather than
// pastes. The nonce is fixed because the key encrypts exactly one message: the
// session key is unique per connection, since the channel binding feeding it
// is.
// The caller passes a buffer with aeadOverhead spare capacity, so this encrypts
// in place. At the paste and connection caps a second full sized copy per
// transfer runs to hundreds of megabytes.
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
