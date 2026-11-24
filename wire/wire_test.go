package wire

import (
	"bytes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"golang.zx2c4.com/wireguard/suite"
)

// deployedLayout is what the current build uses: P-256 public keys, a 16 byte
// GCM tag, and full SHA-256 MACs.
var deployedLayout = Layout{PublicKeySize: 65, AEADOverhead: 16, MACSize: 32}

// The golden bytes below were produced by the RUNNING implementation, through
// encoding/binary over device.MessageInitiation and device.MessageResponse,
// with every field filled with an ascending pattern. They are the oracle for
// wire compatibility: this package must reproduce them byte for byte, or the
// change breaks every deployed peer.
//
// Captured 2026-11-24 via tmpverify/main.go against device at 246 and 157
// bytes, the values of MessageInitiationSize and MessageResponseSize.
const (
	goldenInitiation = "0100000044332211" +
		"404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" +
		"606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80" +
		"808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" +
		"a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
		"c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0" +
		"c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadb" +
		"101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f" +
		"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"

	goldenResponse = "0200000088776655ccbbaa99" +
		"404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" +
		"606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80" +
		"707172737475767778797a7b7c7d7e7f" +
		"101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f" +
		"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
)

func pattern(n int, start byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decoding golden bytes: %v", err)
	}
	return b
}

// goldenInitiationMessage rebuilds the message the golden bytes were made from.
func goldenInitiationMessage() *Initiation {
	l := deployedLayout
	return &Initiation{
		Type:      1,
		Sender:    0x11223344,
		Ephemeral: pattern(l.PublicKeySize, 0x40),
		Static:    pattern(l.staticSize(), 0x80),
		Timestamp: pattern(l.timestampSize(), 0xC0),
		MAC1:      pattern(l.MACSize, 0x10),
		MAC2:      pattern(l.MACSize, 0x20),
	}
}

func goldenResponseMessage() *Response {
	l := deployedLayout
	return &Response{
		Type:      2,
		Sender:    0x55667788,
		Receiver:  0x99aabbcc,
		Ephemeral: pattern(l.PublicKeySize, 0x40),
		Empty:     pattern(l.emptySize(), 0x70),
		MAC1:      pattern(l.MACSize, 0x10),
		MAC2:      pattern(l.MACSize, 0x20),
	}
}

func TestEncodingMatchesTheRunningImplementation(t *testing.T) {
	t.Run("initiation", func(t *testing.T) {
		got, err := deployedLayout.AppendInitiation(nil, goldenInitiationMessage())
		if err != nil {
			t.Fatalf("AppendInitiation: %v", err)
		}
		want := unhex(t, goldenInitiation)
		if len(want) != 246 {
			t.Fatalf("golden initiation is %d bytes, the implementation emits 246", len(want))
		}
		if !bytes.Equal(got, want) {
			t.Errorf("encoding diverges from the deployed wire format\n got %x\nwant %x", got, want)
		}
	})

	t.Run("response", func(t *testing.T) {
		got, err := deployedLayout.AppendResponse(nil, goldenResponseMessage())
		if err != nil {
			t.Fatalf("AppendResponse: %v", err)
		}
		want := unhex(t, goldenResponse)
		if len(want) != 157 {
			t.Fatalf("golden response is %d bytes, the implementation emits 157", len(want))
		}
		if !bytes.Equal(got, want) {
			t.Errorf("encoding diverges from the deployed wire format\n got %x\nwant %x", got, want)
		}
	})
}

func TestSizesMatchTheDeployedConstants(t *testing.T) {
	if got := deployedLayout.InitiationSize(); got != 246 {
		t.Errorf("InitiationSize = %d, MessageInitiationSize is 246", got)
	}
	if got := deployedLayout.ResponseSize(); got != 157 {
		t.Errorf("ResponseSize = %d, MessageResponseSize is 157", got)
	}
}

func TestParseRecoversTheGoldenMessage(t *testing.T) {
	t.Run("initiation", func(t *testing.T) {
		m, err := deployedLayout.ParseInitiation(unhex(t, goldenInitiation))
		if err != nil {
			t.Fatalf("ParseInitiation: %v", err)
		}
		want := goldenInitiationMessage()
		if m.Type != want.Type || m.Sender != want.Sender {
			t.Errorf("header = %d/%#x, want %d/%#x", m.Type, m.Sender, want.Type, want.Sender)
		}
		for _, f := range []struct {
			name      string
			got, want []byte
		}{
			{"ephemeral", m.Ephemeral, want.Ephemeral},
			{"static", m.Static, want.Static},
			{"timestamp", m.Timestamp, want.Timestamp},
			{"mac1", m.MAC1, want.MAC1},
			{"mac2", m.MAC2, want.MAC2},
		} {
			if !bytes.Equal(f.got, f.want) {
				t.Errorf("%s = %x, want %x", f.name, f.got, f.want)
			}
		}
	})

	t.Run("response", func(t *testing.T) {
		m, err := deployedLayout.ParseResponse(unhex(t, goldenResponse))
		if err != nil {
			t.Fatalf("ParseResponse: %v", err)
		}
		want := goldenResponseMessage()
		if m.Type != want.Type || m.Sender != want.Sender || m.Receiver != want.Receiver {
			t.Errorf("header = %d/%#x/%#x, want %d/%#x/%#x",
				m.Type, m.Sender, m.Receiver, want.Type, want.Sender, want.Receiver)
		}
		if !bytes.Equal(m.Ephemeral, want.Ephemeral) {
			t.Errorf("ephemeral = %x, want %x", m.Ephemeral, want.Ephemeral)
		}
		if !bytes.Equal(m.Empty, want.Empty) {
			t.Errorf("empty = %x, want %x", m.Empty, want.Empty)
		}
	})
}

// TestMACOffsetsLocateTheMACs matters because the cookie code computes mac1
// over the prefix that precedes it, using these offsets against the raw packet.
func TestMACOffsetsLocateTheMACs(t *testing.T) {
	raw := unhex(t, goldenInitiation)
	l := deployedLayout

	if got := raw[l.InitiationMAC1Offset() : l.InitiationMAC1Offset()+l.MACSize]; !bytes.Equal(got, pattern(l.MACSize, 0x10)) {
		t.Errorf("mac1 at offset %d = %x", l.InitiationMAC1Offset(), got)
	}
	if got := raw[l.InitiationMAC2Offset() : l.InitiationMAC2Offset()+l.MACSize]; !bytes.Equal(got, pattern(l.MACSize, 0x20)) {
		t.Errorf("mac2 at offset %d = %x", l.InitiationMAC2Offset(), got)
	}

	rawResp := unhex(t, goldenResponse)
	if got := rawResp[l.ResponseMAC1Offset() : l.ResponseMAC1Offset()+l.MACSize]; !bytes.Equal(got, pattern(l.MACSize, 0x10)) {
		t.Errorf("response mac1 at offset %d = %x", l.ResponseMAC1Offset(), got)
	}
	if got := rawResp[l.ResponseMAC2Offset() : l.ResponseMAC2Offset()+l.MACSize]; !bytes.Equal(got, pattern(l.MACSize, 0x20)) {
		t.Errorf("response mac2 at offset %d = %x", l.ResponseMAC2Offset(), got)
	}
}

// TestLayoutsDifferBySuite is the property the whole change exists for: two
// suites produce different message lengths, so a single compile-time constant
// cannot serve both.
func TestLayoutsDifferBySuite(t *testing.T) {
	const (
		fipsName  = ":P-256:HKDF-SHA-256:AEAD_AES_256_GCM"
		stockName = ":X25519:HKDF-BLAKE2S-256:AEAD_CHACHA20_POLY1305"
		id        = "WolfGuard v1 info@wolfssl.com"
	)

	r := suite.NewRegistry()
	fips, err := r.Accept([]byte(fipsName), []byte(id))
	if err != nil {
		t.Fatalf("Accept fips: %v", err)
	}
	stock, err := r.Accept([]byte(stockName), []byte(id))
	if err != nil {
		t.Fatalf("Accept stock: %v", err)
	}

	fl, err := LayoutFor(fips)
	if err != nil {
		t.Fatalf("LayoutFor fips: %v", err)
	}
	sl, err := LayoutFor(stock)
	if err != nil {
		t.Fatalf("LayoutFor stock: %v", err)
	}

	if fl != deployedLayout {
		t.Errorf("fips layout = %+v, want the deployed %+v", fl, deployedLayout)
	}
	if fl.InitiationSize() == sl.InitiationSize() {
		t.Errorf("both suites give initiation size %d; the layouts must differ", fl.InitiationSize())
	}
	if sl.PublicKeySize != 32 {
		t.Errorf("stock public key size = %d, want 32", sl.PublicKeySize)
	}
	t.Logf("fips initiation %d bytes, stock initiation %d bytes", fl.InitiationSize(), sl.InitiationSize())
}

// TestCrossLayoutParseIsRejected is the discrimination guarantee: a message
// built under one layout must not parse under another, which is what stops a
// mis-sliced field being treated as valid.
func TestCrossLayoutParseIsRejected(t *testing.T) {
	stockLayout := Layout{PublicKeySize: 32, AEADOverhead: 16, MACSize: 32}

	raw := unhex(t, goldenInitiation)
	if _, err := stockLayout.ParseInitiation(raw); !errors.Is(err, ErrSize) {
		t.Errorf("parsing a 246 byte initiation under a %d byte layout gave %v, want %v",
			stockLayout.InitiationSize(), err, ErrSize)
	}
}

func TestParseRejectsWrongLength(t *testing.T) {
	raw := unhex(t, goldenInitiation)
	tests := []struct {
		name string
		in   []byte
	}{
		{name: "empty", in: nil},
		{name: "one byte short", in: raw[:len(raw)-1]},
		{name: "one byte long", in: append(append([]byte{}, raw...), 0)},
		{name: "header only", in: raw[:8]},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := deployedLayout.ParseInitiation(tt.in); !errors.Is(err, ErrSize) {
				t.Errorf("ParseInitiation(%d bytes) error = %v, want %v", len(tt.in), err, ErrSize)
			}
			if _, err := deployedLayout.ParseResponse(tt.in); !errors.Is(err, ErrSize) {
				t.Errorf("ParseResponse(%d bytes) error = %v, want %v", len(tt.in), err, ErrSize)
			}
		})
	}
}

func TestAppendRejectsWrongFieldLength(t *testing.T) {
	t.Run("initiation", func(t *testing.T) {
		m := goldenInitiationMessage()
		m.Ephemeral = m.Ephemeral[:len(m.Ephemeral)-1]
		if _, err := deployedLayout.AppendInitiation(nil, m); !errors.Is(err, ErrFieldLength) {
			t.Errorf("error = %v, want %v", err, ErrFieldLength)
		}
	})
	t.Run("response", func(t *testing.T) {
		m := goldenResponseMessage()
		m.MAC2 = nil
		if _, err := deployedLayout.AppendResponse(nil, m); !errors.Is(err, ErrFieldLength) {
			t.Errorf("error = %v, want %v", err, ErrFieldLength)
		}
	})
}

// TestParseCopiesInput guards against a parsed message aliasing the packet
// buffer, which the receive path reuses immediately.
func TestParseCopiesInput(t *testing.T) {
	raw := unhex(t, goldenInitiation)
	m, err := deployedLayout.ParseInitiation(raw)
	if err != nil {
		t.Fatalf("ParseInitiation: %v", err)
	}
	before := append([]byte{}, m.Ephemeral...)

	for i := range raw {
		raw[i] = 0xFF
	}
	if !bytes.Equal(m.Ephemeral, before) {
		t.Error("parsed message aliases the caller's buffer")
	}
}

// TestParsedFieldsCannotBleedIntoEachOther checks the capped subslices: writing
// past the end of one field must not reach the next.
func TestParsedFieldsCannotBleedIntoEachOther(t *testing.T) {
	m, err := deployedLayout.ParseInitiation(unhex(t, goldenInitiation))
	if err != nil {
		t.Fatalf("ParseInitiation: %v", err)
	}
	if got, want := cap(m.Ephemeral), deployedLayout.PublicKeySize; got != want {
		t.Errorf("ephemeral cap = %d, want %d so an append cannot overwrite the static field", got, want)
	}
	if got, want := cap(m.MAC1), deployedLayout.MACSize; got != want {
		t.Errorf("mac1 cap = %d, want %d", got, want)
	}
}

func TestLayoutForRejectsUnusable(t *testing.T) {
	if _, err := LayoutFor(nil); !errors.Is(err, ErrLayout) {
		t.Errorf("LayoutFor(nil) error = %v, want %v", err, ErrLayout)
	}
}

// zeroKEX reports nonsense sizes, standing in for a misconfigured backend.
type zeroKEX struct{}

func (zeroKEX) PublicKeySize() int                                { return 0 }
func (zeroKEX) PrivateKeySize() int                               { return 0 }
func (zeroKEX) GenerateKey() (priv, pub []byte, err error)        { return nil, nil, nil }
func (zeroKEX) PublicKey(priv []byte) ([]byte, error)             { return nil, nil }
func (zeroKEX) SharedSecret(priv, peerPub []byte) ([]byte, error) { return nil, nil }

// TestLayoutForRejectsBrokenSuite covers the two failure paths a misconfigured
// suite reaches: an AEAD that will not construct, and sizes that cannot
// describe a message.
func TestLayoutForRejectsBrokenSuite(t *testing.T) {
	sentinel := errors.New("aead refuses to construct")

	t.Run("aead will not construct", func(t *testing.T) {
		s := &suite.Suite{
			NewHash:     sha256.New,
			NewAEAD:     func([]byte) (cipher.AEAD, error) { return nil, sentinel },
			AEADKeySize: 32,
			KEX:         zeroKEX{},
		}
		if _, err := LayoutFor(s); !errors.Is(err, sentinel) {
			t.Errorf("LayoutFor error = %v, want %v", err, sentinel)
		}
	})

	t.Run("zero sizes", func(t *testing.T) {
		real, err := suite.Resolve("P-256", "HKDF-SHA-256", "AEAD_AES_256_GCM")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		// A working AEAD and hash, but a key exchange reporting no size.
		s := &suite.Suite{
			NewHash:     real.NewHash,
			NewAEAD:     real.NewAEAD,
			AEADKeySize: real.AEADKeySize,
			KEX:         zeroKEX{},
		}
		if _, err := LayoutFor(s); !errors.Is(err, ErrLayout) {
			t.Errorf("LayoutFor error = %v, want %v", err, ErrLayout)
		}
	})
}
