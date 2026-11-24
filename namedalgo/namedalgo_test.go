package namedalgo

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// The expected identifiers below were produced outside this package, by
// coreutils, so that the test does not use the code under test as its own
// oracle:
//
//	printf '%s' 'X25519' | sha256sum | cut -c1-16
//
// If IDLen or the hashing construction changes, these must be recomputed the
// same way rather than copied from a failing test's output.
var oracle = map[Name]string{
	KEXX25519:            "d4a7173ae4e02e0c",
	KEXP256:              "41f405e69015a23e",
	KEXP384:              "4ba65d5678096b13",
	KEXMLKEM768:          "00cd89bb4468bbe1",
	KDFHKDFSHA256:        "ab03530e58c46f20",
	KDFHKDFSHA384:        "846dda118e4724a0",
	KDFHKDFBLAKE2s256:    "abfca1ad3b57943a",
	AEADAES128GCM:        "06d2fe6718730f6c",
	AEADAES256GCM:        "1f5890b6aa46f912",
	AEADChaCha20Poly1305: "937a4fa108b0882b",
}

// mustDecodeID turns an oracle hex string into a PrimitiveID.
func mustDecodeID(t *testing.T, s string) PrimitiveID {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decoding oracle value %q: %v", s, err)
	}
	if len(raw) != IDLen {
		t.Fatalf("oracle value %q is %d bytes, want %d", s, len(raw), IDLen)
	}
	var id PrimitiveID
	copy(id[:], raw)
	return id
}

func TestIDForMatchesExternalOracle(t *testing.T) {
	for _, n := range Registry {
		want, ok := oracle[n]
		if !ok {
			t.Fatalf("Registry contains %q with no oracle value; recompute it with sha256sum", n)
		}
		t.Run(string(n), func(t *testing.T) {
			if got := IDFor(n); got != mustDecodeID(t, want) {
				t.Errorf("IDFor(%q) = %x, want %s", n, got, want)
			}
		})
	}
}

func TestRegistryIsFullyCovered(t *testing.T) {
	if len(oracle) != len(Registry) {
		t.Errorf("oracle has %d entries, Registry has %d; every name needs an externally computed value",
			len(oracle), len(Registry))
	}
}

func TestVectorRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		in   Vector
	}{
		{
			name: "single offer",
			in:   Vector{OfferFor(KEXP256, KDFHKDFSHA256, AEADAES256GCM)},
		},
		{
			name: "the two suites that exist today",
			in: Vector{
				OfferFor(KEXP256, KDFHKDFSHA256, AEADAES256GCM),
				OfferFor(KEXX25519, KDFHKDFBLAKE2s256, AEADChaCha20Poly1305),
			},
		},
		{
			name: "at the offer limit",
			in: func() Vector {
				v := make(Vector, 0, MaxOffers)
				for i := 0; i < MaxOffers; i++ {
					v = append(v, OfferFor(KEXP256, KDFHKDFSHA256, AEADAES256GCM))
				}
				return v
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := tt.in.Append(nil)
			if err != nil {
				t.Fatalf("Append: %v", err)
			}
			if len(wire) != tt.in.EncodedLen() {
				t.Errorf("encoded %d bytes, EncodedLen said %d", len(wire), tt.in.EncodedLen())
			}

			got, used, err := Parse(wire)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if used != len(wire) {
				t.Errorf("Parse consumed %d of %d bytes", used, len(wire))
			}
			if len(got) != len(tt.in) {
				t.Fatalf("parsed %d offers, want %d", len(got), len(tt.in))
			}
			for i := range got {
				if got[i] != tt.in[i] {
					t.Errorf("offer %d: got %+v, want %+v", i, got[i], tt.in[i])
				}
			}
		})
	}
}

// TestWireFormatIsByteExact builds the expected encoding by hand from the
// external oracle values, so a change to the wire layout fails here even if
// Append and Parse still agree with each other.
func TestWireFormatIsByteExact(t *testing.T) {
	v := Vector{
		OfferFor(KEXP256, KDFHKDFSHA256, AEADAES256GCM),
		OfferFor(KEXX25519, KDFHKDFBLAKE2s256, AEADChaCha20Poly1305),
	}

	var want []byte
	want = append(want, 0x02)
	for _, h := range []string{
		oracle[KEXP256], oracle[KDFHKDFSHA256], oracle[AEADAES256GCM],
		oracle[KEXX25519], oracle[KDFHKDFBLAKE2s256], oracle[AEADChaCha20Poly1305],
	} {
		id := mustDecodeID(t, h)
		want = append(want, id[:]...)
	}

	got, err := v.Append(nil)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("wire encoding mismatch\n got %x\nwant %x", got, want)
	}
	if len(want) != 1+2*OfferLen {
		t.Errorf("hand-built encoding is %d bytes, expected %d", len(want), 1+2*OfferLen)
	}
}

// TestParseLocatesTrailer checks the consumed-byte count, which is what lets a
// caller find the ephemeral that follows the vector once the suite, and
// therefore the ephemeral's length, is known.
func TestParseLocatesTrailer(t *testing.T) {
	v := Vector{OfferFor(KEXP256, KDFHKDFSHA256, AEADAES256GCM)}
	trailer := []byte("ephemeral-goes-here")

	wire, err := v.Append(nil)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	wire = append(wire, trailer...)

	_, used, err := Parse(wire)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := wire[used:]; !bytes.Equal(got, trailer) {
		t.Errorf("trailer after %d bytes = %q, want %q", used, got, trailer)
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	validOffer := make([]byte, OfferLen)

	tests := []struct {
		name string
		in   []byte
		want error
	}{
		{
			name: "empty buffer",
			in:   nil,
			want: ErrShortBuffer,
		},
		{
			name: "zero offers",
			in:   []byte{0x00},
			want: ErrEmptyVector,
		},
		{
			name: "one past the limit",
			in:   append([]byte{MaxOffers + 1}, bytes.Repeat(validOffer, MaxOffers+1)...),
			want: ErrTooManyOffers,
		},
		{
			name: "count is the maximum byte value",
			in:   []byte{0xff},
			want: ErrTooManyOffers,
		},
		{
			name: "count claims more than the buffer holds",
			in:   append([]byte{0x02}, validOffer...),
			want: ErrShortBuffer,
		},
		{
			name: "offer truncated by one byte",
			in:   append([]byte{0x01}, validOffer[:OfferLen-1]...),
			want: ErrShortBuffer,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, used, err := Parse(tt.in)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Parse error = %v, want %v", err, tt.want)
			}
			if v != nil {
				t.Errorf("Parse returned %d offers alongside an error", len(v))
			}
			if used != 0 {
				t.Errorf("Parse consumed %d bytes alongside an error", used)
			}
		})
	}
}

func TestAppendRejectsUnsendableVectors(t *testing.T) {
	tests := []struct {
		name string
		in   Vector
		want error
	}{
		{
			name: "empty",
			in:   Vector{},
			want: ErrEmptyVector,
		},
		{
			name: "nil",
			in:   nil,
			want: ErrEmptyVector,
		},
		{
			name: "one past the limit",
			in:   make(Vector, MaxOffers+1),
			want: ErrTooManyOffers,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.in.Append(nil)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Append error = %v, want %v", err, tt.want)
			}
			if got != nil {
				t.Errorf("Append returned %d bytes alongside an error", len(got))
			}
		})
	}
}

// TestAppendPreservesDestination guards the aliasing rule: Append must extend
// what it is given rather than overwrite it, because the caller is building a
// handshake message around the vector.
func TestAppendPreservesDestination(t *testing.T) {
	prefix := []byte{0xde, 0xad, 0xbe, 0xef}
	dst := make([]byte, len(prefix), 64)
	copy(dst, prefix)

	v := Vector{OfferFor(KEXP256, KDFHKDFSHA256, AEADAES256GCM)}
	got, err := v.Append(dst)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if !bytes.Equal(got[:len(prefix)], prefix) {
		t.Errorf("prefix corrupted: got %x, want %x", got[:len(prefix)], prefix)
	}
	if len(got) != len(prefix)+v.EncodedLen() {
		t.Errorf("length %d, want %d", len(got), len(prefix)+v.EncodedLen())
	}
}

func TestCheckCollisionsOnRealRegistry(t *testing.T) {
	if err := CheckCollisions(Registry); err != nil {
		t.Errorf("Registry has a truncated-id collision at IDLen=%d: %v", IDLen, err)
	}
}

func TestCheckCollisionsAllowsRepeatedName(t *testing.T) {
	if err := CheckCollisions([]Name{KEXP256, KEXP256}); err != nil {
		t.Errorf("the same name twice is not a collision, got %v", err)
	}
}

// TestCheckCollisionsDetectsCollision reaches the collision branch by
// substituting the id function, since crafting two registry names that really
// collide in IDLen bytes of SHA-256 is not feasible.
func TestCheckCollisionsDetectsCollision(t *testing.T) {
	const (
		first  Name = "FIRST-NAME"
		second Name = "SECOND-NAME"
	)

	original := idFor
	t.Cleanup(func() { idFor = original })
	idFor = func(Name) PrimitiveID { return PrimitiveID{} }

	err := CheckCollisions([]Name{first, second})
	if !errors.Is(err, ErrCollision) {
		t.Fatalf("CheckCollisions error = %v, want %v", err, ErrCollision)
	}
	for _, want := range []Name{first, second} {
		if !bytes.Contains([]byte(err.Error()), []byte(want)) {
			t.Errorf("error %q does not name the colliding entry %q", err, want)
		}
	}
}
