package wire

import (
	"bytes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"golang.zx2c4.com/wireguard/suite"
	"golang.zx2c4.com/wireguard/suitestd"
)

// deployedLayout is what the current build uses: P-256 public keys, a 16 byte
// GCM tag, and full SHA-256 MACs.
func init() { suitestd.Register() }

var deployedLayout = Layout{PublicKeySize: 65, AEADOverhead: 16, MACSize: 32, AEADNonceSize: 16}

// goldenFile holds the deployed handshake layout, marshalled with
// encoding/binary from fixed-size structs frozen inside
// wire/internal/gengolden. It is the oracle for wire compatibility: this
// package must reproduce those bytes exactly, or the change breaks every
// deployed peer.
//
// It used to be captured from the device package's own message structs. Those
// fields are now slices sized from the cipher suite, which encoding/binary
// cannot marshal, and capturing them through this package would have made the
// codec its own oracle. So the layout is declared in the generator instead,
// which is also the stronger arrangement: it is frozen by deployment, and
// freezing it by declaration stops it following a refactor.
//
// The tests cannot produce it here, because device imports wire and the test
// binary would be an import cycle. Hence a committed file written by a
// separate command.
//
// 'cd wire && go run ./internal/gengolden' re-verifies the file without
// touching it, comparing the message sizes and bytes rather than the file's
// text, so an edit to the note above is not reported as the wire format
// moving. Only -write rewrites it.
const goldenFile = "testdata/golden_wire.json"

type goldenMessage struct {
	Size int    `json:"size"`
	Hex  string `json:"hex"`
}

type goldenData struct {
	Initiation goldenMessage `json:"initiation"`
	Response   goldenMessage `json:"response"`
}

func loadGolden(t *testing.T) goldenData {
	t.Helper()
	raw, err := os.ReadFile(goldenFile)
	if err != nil {
		t.Fatalf("reading %s: %v (regenerate with: go generate ./wire/...)", goldenFile, err)
	}
	var g goldenData
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatalf("parsing %s: %v", goldenFile, err)
	}
	if g.Initiation.Hex == "" || g.Response.Hex == "" {
		t.Fatalf("%s is missing message bytes", goldenFile)
	}
	return g
}

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
		want := unhex(t, loadGolden(t).Initiation.Hex)
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
		want := unhex(t, loadGolden(t).Response.Hex)
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
	/* 72 was MessageCookieReplySize, a constant every suite had to share until
	 * the reply was framed from one. The deployed suite still has to produce
	 * exactly it, or a cookie reply stops being recognised in the field. */
	if got := deployedLayout.CookieReplySize(); got != 72 {
		t.Errorf("CookieReplySize = %d, MessageCookieReplySize was 72", got)
	}
}

func TestParseRecoversTheGoldenMessage(t *testing.T) {
	t.Run("initiation", func(t *testing.T) {
		m, err := deployedLayout.ParseInitiation(unhex(t, loadGolden(t).Initiation.Hex))
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
		m, err := deployedLayout.ParseResponse(unhex(t, loadGolden(t).Response.Hex))
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
	raw := unhex(t, loadGolden(t).Initiation.Hex)
	l := deployedLayout

	if got := raw[l.InitiationMAC1Offset() : l.InitiationMAC1Offset()+l.MACSize]; !bytes.Equal(got, pattern(l.MACSize, 0x10)) {
		t.Errorf("mac1 at offset %d = %x", l.InitiationMAC1Offset(), got)
	}
	if got := raw[l.InitiationMAC2Offset() : l.InitiationMAC2Offset()+l.MACSize]; !bytes.Equal(got, pattern(l.MACSize, 0x20)) {
		t.Errorf("mac2 at offset %d = %x", l.InitiationMAC2Offset(), got)
	}

	rawResp := unhex(t, loadGolden(t).Response.Hex)
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
	stockLayout := Layout{PublicKeySize: 32, AEADOverhead: 16, MACSize: 32, AEADNonceSize: 12}

	raw := unhex(t, loadGolden(t).Initiation.Hex)
	if _, err := stockLayout.ParseInitiation(raw); !errors.Is(err, ErrSize) {
		t.Errorf("parsing a 246 byte initiation under a %d byte layout gave %v, want %v",
			stockLayout.InitiationSize(), err, ErrSize)
	}
}

func TestParseRejectsWrongLength(t *testing.T) {
	raw := unhex(t, loadGolden(t).Initiation.Hex)
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
	raw := unhex(t, loadGolden(t).Initiation.Hex)
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
	m, err := deployedLayout.ParseInitiation(unhex(t, loadGolden(t).Initiation.Hex))
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

// TestCookieReplyFramingFollowsTheAEAD is the fact that decides how a cookie
// reply has to be routed on receipt.
//
// Its length follows the AEAD's nonce and tag, not the suite's hash, because
// the cookie inside it is truncated to a fixed length. So two suites that
// differ only in hash frame replies of the same size, which is exactly the
// pair a migration serves. A reply's length therefore cannot select its suite
// the way an initiation's does, and the receive path uses the index the reply
// carries instead.
func TestCookieReplyFramingFollowsTheAEAD(t *testing.T) {
	const id = "WolfGuard v1 info@wolfssl.com"
	r := suite.NewRegistry()

	layoutOf := func(name string) Layout {
		t.Helper()
		s, err := r.Accept([]byte(name), []byte(id))
		if err != nil {
			t.Fatalf("Accept %q: %v", name, err)
		}
		l, err := LayoutFor(s)
		if err != nil {
			t.Fatalf("LayoutFor %q: %v", name, err)
		}
		return l
	}

	gcm256 := layoutOf(":P-256:HKDF-SHA-256:AEAD_AES_256_GCM")
	gcm384 := layoutOf(":P-256:HKDF-SHA-384:AEAD_AES_256_GCM")
	chacha := layoutOf(":P-256:HKDF-SHA-384:AEAD_CHACHA20_POLY1305")

	if gcm256.InitiationSize() == gcm384.InitiationSize() {
		t.Fatal("the two AES suites frame identical initiations, so this proves nothing about the hash")
	}
	if a, b := gcm256.CookieReplySize(), gcm384.CookieReplySize(); a != b {
		t.Errorf("changing the hash moved the reply from %d to %d bytes; the cookie is truncated to a fixed length, so it should not", a, b)
	}

	if chacha.CookieReplySize() == gcm384.CookieReplySize() {
		t.Error("ChaCha20-Poly1305 frames the same reply as AES-GCM, but its nonce is 12 bytes against 16")
	}
	if got, want := chacha.CookieReplySize(), 4+4+12+CookieSize+16; got != want {
		t.Errorf("chacha reply = %d bytes, want %d", got, want)
	}
	t.Logf("aes-gcm reply %d bytes, chacha reply %d bytes",
		gcm256.CookieReplySize(), chacha.CookieReplySize())
}

// TestCookieReplyRoundTrip covers the codec, and the index read that has to
// work before the suite is known.
func TestCookieReplyRoundTrip(t *testing.T) {
	l := deployedLayout
	m := &CookieReply{
		Type:     3,
		Receiver: 0xDEADBEEF,
		Nonce:    bytes.Repeat([]byte{0xA1}, l.AEADNonceSize),
		Cookie:   bytes.Repeat([]byte{0xB2}, CookieSize+l.AEADOverhead),
	}

	packet, err := l.AppendCookieReply(nil, m)
	if err != nil {
		t.Fatalf("AppendCookieReply: %v", err)
	}
	if len(packet) != l.CookieReplySize() {
		t.Fatalf("encoded %d bytes, CookieReplySize says %d", len(packet), l.CookieReplySize())
	}

	/* The index has to come out of the bytes alone, since a receiver reads it
	 * to find the peer whose suite says how the rest is framed. */
	if got, ok := CookieReplyReceiver(packet); !ok || got != m.Receiver {
		t.Errorf("CookieReplyReceiver = %d, %v; want %d, true", got, ok, m.Receiver)
	}
	if _, ok := CookieReplyReceiver(packet[:7]); ok {
		t.Error("an index was read out of 7 bytes")
	}

	back, err := l.ParseCookieReply(packet)
	if err != nil {
		t.Fatalf("ParseCookieReply: %v", err)
	}
	if back.Type != m.Type || back.Receiver != m.Receiver ||
		!bytes.Equal(back.Nonce, m.Nonce) || !bytes.Equal(back.Cookie, m.Cookie) {
		t.Errorf("the round trip changed the message\n got %+v\nwant %+v", back, m)
	}

	/* A reply framed under a shorter nonce must be rejected rather than
	 * mis-sliced, which is the same guarantee the handshake messages have. */
	shortNonce := Layout{PublicKeySize: 65, AEADOverhead: 16, MACSize: 32, AEADNonceSize: 12}
	if _, err := shortNonce.ParseCookieReply(packet); !errors.Is(err, ErrSize) {
		t.Errorf("a 72 byte reply parsed under a 12 byte nonce layout: %v", err)
	}
	if _, err := l.AppendCookieReply(nil, &CookieReply{Nonce: m.Nonce[:4], Cookie: m.Cookie}); !errors.Is(err, ErrFieldLength) {
		t.Errorf("encoding accepted a nonce of the wrong length: %v", err)
	}
}
