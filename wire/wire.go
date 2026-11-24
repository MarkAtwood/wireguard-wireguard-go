// Package wire encodes and decodes the handshake messages when their field
// sizes are a property of the suite in force rather than of the build.
//
// The existing code marshals these messages with encoding/binary over structs
// of fixed-size arrays. That cannot express a suite-dependent layout: binary
// reflects over fixed-size data, so it has no way to say that the ephemeral is
// 32 bytes under one suite and 65 under another, nor to size the field from a
// value read earlier in the same message. Hence explicit encoding here.
//
// The encoding is otherwise unchanged. For the layout the current build uses,
// the bytes this package produces are identical to what encoding/binary
// produces today, which the tests assert against golden bytes captured from the
// running implementation. Nothing about the protocol moves; only the question of
// where the sizes come from.
//
// Three quantities vary by suite:
//
//   - PublicKeySize, from the key exchange, which sets the ephemeral field and
//     the plaintext half of the encrypted static field.
//   - AEADOverhead, the authentication tag length, which extends every
//     encrypted field.
//   - MACSize, the length of mac1 and mac2.
//
// MACSize is not derivable from the handshake name, and implementations
// genuinely disagree on it: this build uses the hash's full output, 32 bytes of
// SHA-256, while stock WireGuard truncates to 16. LayoutFor takes the full hash
// output, which reproduces the deployed wolfGuard layout exactly. That
// divergence is one of the reasons interoperating with stock WireGuard is not
// free, and it is recorded here rather than hidden.
//
// See DESIGN-2026-runtime-multisuite.md in the WOLFGUARD-AGILITY project.
package wire

//go:generate go run ./internal/gengolden -write

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.zx2c4.com/wireguard/suite"
)

// Errors reported when a message does not match the layout. A peer sending one
// is malformed or using a suite this device did not expect, and the handshake
// is dropped.
var (
	ErrSize        = errors.New("wire: message length does not match the layout")
	ErrFieldLength = errors.New("wire: field length does not match the layout")
	ErrLayout      = errors.New("wire: layout is not usable")
)

// Layout is the set of suite-dependent field sizes for one suite.
type Layout struct {
	PublicKeySize int
	AEADOverhead  int
	MACSize       int
}

// LayoutFor derives the layout from a resolved suite.
//
// The AEAD's overhead is read from a constructed instance rather than assumed,
// since it is the authority on its own tag length. This runs once per suite, at
// configuration time, not per packet.
func LayoutFor(s *suite.Suite) (Layout, error) {
	if s == nil {
		return Layout{}, fmt.Errorf("nil suite: %w", ErrLayout)
	}

	aead, err := s.NewAEAD(make([]byte, s.AEADKeySize))
	if err != nil {
		return Layout{}, fmt.Errorf("constructing the suite's aead to read its overhead: %w", err)
	}

	l := Layout{
		PublicKeySize: s.KEX.PublicKeySize(),
		AEADOverhead:  aead.Overhead(),
		MACSize:       s.NewHash().Size(),
	}
	if l.PublicKeySize <= 0 || l.AEADOverhead <= 0 || l.MACSize <= 0 {
		return Layout{}, fmt.Errorf("public key %d, overhead %d, mac %d: %w",
			l.PublicKeySize, l.AEADOverhead, l.MACSize, ErrLayout)
	}
	return l, nil
}

// Field sizes derived from the layout.
func (l Layout) staticSize() int    { return l.PublicKeySize + l.AEADOverhead }
func (l Layout) timestampSize() int { return timestampPlaintextSize + l.AEADOverhead }
func (l Layout) emptySize() int     { return l.AEADOverhead }

// timestampPlaintextSize is the tai64n timestamp length. It does not vary by
// suite, so it stays a constant here rather than becoming a layout field.
const timestampPlaintextSize = 12

// InitiationSize is the encoded length of a handshake initiation.
func (l Layout) InitiationSize() int {
	return 4 + 4 + l.PublicKeySize + l.staticSize() + l.timestampSize() + 2*l.MACSize
}

// ResponseSize is the encoded length of a handshake response.
func (l Layout) ResponseSize() int {
	return 4 + 4 + 4 + l.PublicKeySize + l.emptySize() + 2*l.MACSize
}

// InitiationMAC1Offset is where mac1 begins in an initiation, which is also the
// length of the prefix mac1 is computed over.
func (l Layout) InitiationMAC1Offset() int {
	return l.InitiationSize() - 2*l.MACSize
}

// InitiationMAC2Offset is where mac2 begins in an initiation.
func (l Layout) InitiationMAC2Offset() int {
	return l.InitiationSize() - l.MACSize
}

// ResponseMAC1Offset is where mac1 begins in a response.
func (l Layout) ResponseMAC1Offset() int {
	return l.ResponseSize() - 2*l.MACSize
}

// ResponseMAC2Offset is where mac2 begins in a response.
func (l Layout) ResponseMAC2Offset() int {
	return l.ResponseSize() - l.MACSize
}

// Initiation is a handshake initiation message.
//
// Every byte slice is exactly the length the layout prescribes. A parsed
// Initiation owns its bytes, so the caller may reuse the packet buffer at once.
type Initiation struct {
	Type      uint32
	Sender    uint32
	Ephemeral []byte
	Static    []byte
	Timestamp []byte
	MAC1      []byte
	MAC2      []byte
}

// Response is a handshake response message.
type Response struct {
	Type      uint32
	Sender    uint32
	Receiver  uint32
	Ephemeral []byte
	Empty     []byte
	MAC1      []byte
	MAC2      []byte
}

// field is one slice to encode, named for the error message.
type field struct {
	name string
	b    []byte
	want int
}

func appendFields(dst []byte, fields []field) ([]byte, error) {
	for _, f := range fields {
		if len(f.b) != f.want {
			return nil, fmt.Errorf("%s is %d bytes, layout wants %d: %w", f.name, len(f.b), f.want, ErrFieldLength)
		}
		dst = append(dst, f.b...)
	}
	return dst, nil
}

// AppendInitiation encodes m onto dst and returns the extended slice.
func (l Layout) AppendInitiation(dst []byte, m *Initiation) ([]byte, error) {
	dst = binary.LittleEndian.AppendUint32(dst, m.Type)
	dst = binary.LittleEndian.AppendUint32(dst, m.Sender)
	return appendFields(dst, []field{
		{"ephemeral", m.Ephemeral, l.PublicKeySize},
		{"static", m.Static, l.staticSize()},
		{"timestamp", m.Timestamp, l.timestampSize()},
		{"mac1", m.MAC1, l.MACSize},
		{"mac2", m.MAC2, l.MACSize},
	})
}

// ParseInitiation decodes an initiation of exactly InitiationSize bytes.
//
// The length check is exact, matching the equality check the current receive
// path applies against its single compile-time constant. A peer whose message
// is a different length is using a different layout, so it is rejected here
// rather than mis-sliced.
func (l Layout) ParseInitiation(b []byte) (*Initiation, error) {
	if want := l.InitiationSize(); len(b) != want {
		return nil, fmt.Errorf("initiation is %d bytes, layout wants %d: %w", len(b), want, ErrSize)
	}

	owned := make([]byte, len(b))
	copy(owned, b)

	m := &Initiation{
		Type:   binary.LittleEndian.Uint32(owned[0:4]),
		Sender: binary.LittleEndian.Uint32(owned[4:8]),
	}
	off := 8
	for _, dst := range []struct {
		p *[]byte
		n int
	}{
		{&m.Ephemeral, l.PublicKeySize},
		{&m.Static, l.staticSize()},
		{&m.Timestamp, l.timestampSize()},
		{&m.MAC1, l.MACSize},
		{&m.MAC2, l.MACSize},
	} {
		*dst.p = owned[off : off+dst.n : off+dst.n]
		off += dst.n
	}
	return m, nil
}

// AppendResponse encodes m onto dst and returns the extended slice.
func (l Layout) AppendResponse(dst []byte, m *Response) ([]byte, error) {
	dst = binary.LittleEndian.AppendUint32(dst, m.Type)
	dst = binary.LittleEndian.AppendUint32(dst, m.Sender)
	dst = binary.LittleEndian.AppendUint32(dst, m.Receiver)
	return appendFields(dst, []field{
		{"ephemeral", m.Ephemeral, l.PublicKeySize},
		{"empty", m.Empty, l.emptySize()},
		{"mac1", m.MAC1, l.MACSize},
		{"mac2", m.MAC2, l.MACSize},
	})
}

// ParseResponse decodes a response of exactly ResponseSize bytes.
func (l Layout) ParseResponse(b []byte) (*Response, error) {
	if want := l.ResponseSize(); len(b) != want {
		return nil, fmt.Errorf("response is %d bytes, layout wants %d: %w", len(b), want, ErrSize)
	}

	owned := make([]byte, len(b))
	copy(owned, b)

	m := &Response{
		Type:     binary.LittleEndian.Uint32(owned[0:4]),
		Sender:   binary.LittleEndian.Uint32(owned[4:8]),
		Receiver: binary.LittleEndian.Uint32(owned[8:12]),
	}
	off := 12
	for _, dst := range []struct {
		p *[]byte
		n int
	}{
		{&m.Ephemeral, l.PublicKeySize},
		{&m.Empty, l.emptySize()},
		{&m.MAC1, l.MACSize},
		{&m.MAC2, l.MACSize},
	} {
		*dst.p = owned[off : off+dst.n : off+dst.n]
		off += dst.n
	}
	return m, nil
}
