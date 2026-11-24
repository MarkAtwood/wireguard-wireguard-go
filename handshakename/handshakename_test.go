package handshakename

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// The two suites that exist today, written as dynamic names.
const (
	fipsName  = ":P-256:HKDF-SHA-256:AEAD_AES_256_GCM"
	stockName = ":X25519:HKDF-BLAKE2S-256:AEAD_CHACHA20_POLY1305"
)

// chainKeyOracle holds SHA-256 of each name, computed outside this package so
// that the chaining-key contract is not checked against the code that
// implements it:
//
//	printf '%s' ':P-256:HKDF-SHA-256:AEAD_AES_256_GCM' | sha256sum
//
// These values are the whole point of the design: the initial chaining key is
// the hash of the bytes received, so a change to the name or to what Raw
// returns must break here.
var chainKeyOracle = map[string]string{
	fipsName:  "dbcd34997320f3f623e325b2b8c4bd902d7f70b7e650796c2031c54a3294ecac",
	stockName: "35a74344b36395b1e554b25756a8a1093370cb099151ab27c9ce6e4e34a2ce62",
}

func TestRawHashesToExternalOracle(t *testing.T) {
	for name, want := range chainKeyOracle {
		t.Run(name, func(t *testing.T) {
			n, err := Parse([]byte(name))
			if err != nil {
				t.Fatalf("Parse(%q): %v", name, err)
			}
			sum := sha256.Sum256(n.Raw())
			if got := hex.EncodeToString(sum[:]); got != want {
				t.Errorf("SHA-256(Raw()) = %s, want %s", got, want)
			}
		})
	}
}

func TestParseExtractsPrimitives(t *testing.T) {
	tests := []struct {
		name           string
		in             string
		kex, kdf, aead string
	}{
		{
			name: "fips suite",
			in:   fipsName,
			kex:  "P-256", kdf: "HKDF-SHA-256", aead: "AEAD_AES_256_GCM",
		},
		{
			name: "stock suite",
			in:   stockName,
			kex:  "X25519", kdf: "HKDF-BLAKE2S-256", aead: "AEAD_CHACHA20_POLY1305",
		},
		{
			name: "hybrid key exchange keeps its plus sign",
			in:   ":X25519+ML-KEM-768:HKDF-SHA-256:AEAD_AES_256_GCM",
			kex:  "X25519+ML-KEM-768", kdf: "HKDF-SHA-256", aead: "AEAD_AES_256_GCM",
		},
		{
			name: "shortest legal name",
			in:   ":a:b:c",
			kex:  "a", kdf: "b", aead: "c",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := Parse([]byte(tt.in))
			if err != nil {
				t.Fatalf("Parse(%q): %v", tt.in, err)
			}
			if n.KEX() != tt.kex {
				t.Errorf("KEX() = %q, want %q", n.KEX(), tt.kex)
			}
			if n.KDF() != tt.kdf {
				t.Errorf("KDF() = %q, want %q", n.KDF(), tt.kdf)
			}
			if n.AEAD() != tt.aead {
				t.Errorf("AEAD() = %q, want %q", n.AEAD(), tt.aead)
			}
			if !bytes.Equal(n.Raw(), []byte(tt.in)) {
				t.Errorf("Raw() = %q, want the received bytes %q", n.Raw(), tt.in)
			}
			if n.Len() != len(tt.in) {
				t.Errorf("Len() = %d, want %d", n.Len(), len(tt.in))
			}
		})
	}
}

func TestParseRejects(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want error
	}{
		{name: "empty", in: "", want: ErrTooShort},
		{name: "lead only", in: ":", want: ErrTooShort},
		{name: "legacy fixed string has no lead", in: "Noise_IKpsk2_SECP256R1_AesGcm_SHA256", want: ErrNoLead},
		{name: "lead in the wrong place", in: "P-256:HKDF-SHA-256:AEAD_AES_256_GCM", want: ErrNoLead},
		{name: "two primitives", in: ":P-256:HKDF-SHA-256", want: ErrFieldCount},
		{name: "four primitives", in: ":P-256:HKDF-SHA-256:AEAD_AES_256_GCM:extra", want: ErrFieldCount},
		{name: "empty first primitive", in: "::HKDF-SHA-256:AEAD_AES_256_GCM", want: ErrEmptyField},
		{name: "empty middle primitive", in: ":P-256::AEAD_AES_256_GCM", want: ErrEmptyField},
		{name: "empty trailing primitive", in: ":P-256:HKDF-SHA-256:", want: ErrEmptyField},
		{name: "space", in: ":P-256:HKDF SHA-256:AEAD_AES_256_GCM", want: ErrBadCharacter},
		{name: "embedded NUL", in: ":P-256:HKDF-SHA-256:AEAD\x00GCM", want: ErrBadCharacter},
		{name: "newline", in: ":P-256:HKDF-SHA-256:AEAD_AES_256_GCM\n", want: ErrBadCharacter},
		{name: "non-ASCII", in: ":P-256:HKDF-SHA-256:AEAD_AES_256_GCM\xff", want: ErrBadCharacter},
		{name: "slash", in: ":../../etc/passwd:HKDF-SHA-256:AEAD_AES_256_GCM", want: ErrBadCharacter},
		{
			name: "over the length cap",
			in:   ":" + strings.Repeat("A", MaxLen) + ":b:c",
			want: ErrTooLong,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := Parse([]byte(tt.in))
			if !errors.Is(err, tt.want) {
				t.Fatalf("Parse(%q) error = %v, want %v", tt.in, err, tt.want)
			}
			if n.Raw() != nil {
				t.Errorf("Parse returned a usable Name alongside an error: %q", n.Raw())
			}
		})
	}
}

// TestParseAcceptsExactlyTheCap pins the boundary, since an off-by-one in the
// cap is the kind of thing that only shows up against a hostile peer.
func TestParseAcceptsExactlyTheCap(t *testing.T) {
	// ":" + kex + ":b:c" == MaxLen total.
	kex := strings.Repeat("A", MaxLen-len(":b:c")-1)
	in := ":" + kex + ":b:c"
	if len(in) != MaxLen {
		t.Fatalf("test constructed a %d byte name, want exactly %d", len(in), MaxLen)
	}

	n, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("Parse at exactly MaxLen: %v", err)
	}
	if n.KEX() != kex {
		t.Errorf("KEX() = %q, want %q", n.KEX(), kex)
	}

	if _, err := Parse([]byte(in + "X")); !errors.Is(err, ErrTooLong) {
		t.Errorf("Parse at MaxLen+1 error = %v, want %v", err, ErrTooLong)
	}
}

// TestParseCopiesInput is the aliasing guard. The caller's buffer is a packet
// buffer that will be reused, so a Name holding a reference to it would see its
// own chaining-key input change underneath it.
func TestParseCopiesInput(t *testing.T) {
	buf := []byte(fipsName)
	n, err := Parse(buf)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	before := sha256.Sum256(n.Raw())
	for i := range buf {
		buf[i] = 'Z'
	}
	after := sha256.Sum256(n.Raw())

	if before != after {
		t.Error("Name aliases the caller's buffer: overwriting it changed what Raw returns")
	}
	if n.KEX() != "P-256" {
		t.Errorf("KEX() = %q after the caller's buffer was overwritten, want %q", n.KEX(), "P-256")
	}
}

func TestBuildRoundTrips(t *testing.T) {
	tests := []struct {
		name           string
		kex, kdf, aead string
		want           string
	}{
		{name: "fips suite", kex: "P-256", kdf: "HKDF-SHA-256", aead: "AEAD_AES_256_GCM", want: fipsName},
		{name: "stock suite", kex: "X25519", kdf: "HKDF-BLAKE2S-256", aead: "AEAD_CHACHA20_POLY1305", want: stockName},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := Build(tt.kex, tt.kdf, tt.aead)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			if string(n.Raw()) != tt.want {
				t.Fatalf("Build produced %q, want %q", n.Raw(), tt.want)
			}

			again, err := Parse(n.Raw())
			if err != nil {
				t.Fatalf("Parse of a Built name: %v", err)
			}
			if !bytes.Equal(again.Raw(), n.Raw()) {
				t.Errorf("round trip changed the bytes: %q then %q", n.Raw(), again.Raw())
			}
			if again.KEX() != tt.kex || again.KDF() != tt.kdf || again.AEAD() != tt.aead {
				t.Errorf("round trip changed the fields: %q/%q/%q", again.KEX(), again.KDF(), again.AEAD())
			}
		})
	}
}

func TestBuildRejects(t *testing.T) {
	tests := []struct {
		name           string
		kex, kdf, aead string
		want           error
	}{
		{name: "empty kex", kdf: "HKDF-SHA-256", aead: "AEAD_AES_256_GCM", want: ErrEmptyField},
		{name: "empty kdf", kex: "P-256", aead: "AEAD_AES_256_GCM", want: ErrEmptyField},
		{name: "empty aead", kex: "P-256", kdf: "HKDF-SHA-256", want: ErrEmptyField},
		{
			name: "colon smuggled into a field",
			kex:  "P-256:extra", kdf: "HKDF-SHA-256", aead: "AEAD_AES_256_GCM",
			want: ErrFieldCount,
		},
		{
			name: "disallowed byte in a field",
			kex:  "P 256", kdf: "HKDF-SHA-256", aead: "AEAD_AES_256_GCM",
			want: ErrBadCharacter,
		},
		{
			name: "field long enough to breach the cap",
			kex:  strings.Repeat("A", MaxLen), kdf: "b", aead: "c",
			want: ErrTooLong,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := Build(tt.kex, tt.kdf, tt.aead)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Build error = %v, want %v", err, tt.want)
			}
			if n.Raw() != nil {
				t.Errorf("Build returned a usable Name alongside an error: %q", n.Raw())
			}
		})
	}
}

// TestDistinctNamesDeriveDistinctChainKeys is the domain-separation property:
// two suites must never share an initial chaining key, and a dynamic name must
// never collide with a legacy fixed string.
func TestDistinctNamesDeriveDistinctChainKeys(t *testing.T) {
	names := []string{
		fipsName,
		stockName,
		":X25519+ML-KEM-768:HKDF-SHA-256:AEAD_AES_256_GCM",
	}

	seen := make(map[[sha256.Size]byte]string, len(names)+2)
	for _, legacy := range []string{
		"Noise_IKpsk2_SECP256R1_AesGcm_SHA256",
		"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s",
	} {
		seen[sha256.Sum256([]byte(legacy))] = legacy
	}

	for _, name := range names {
		n, err := Parse([]byte(name))
		if err != nil {
			t.Fatalf("Parse(%q): %v", name, err)
		}
		key := sha256.Sum256(n.Raw())
		if prev, ok := seen[key]; ok {
			t.Errorf("%q and %q derive the same chaining key", prev, name)
		}
		seen[key] = name
	}
}

// TestStringMatchesRaw locks the invariant documented on String: it exists for
// logs, and it must stay byte-identical to Raw so that nobody can quietly start
// hashing it instead.
func TestStringMatchesRaw(t *testing.T) {
	for _, name := range []string{fipsName, stockName, ":a:b:c"} {
		t.Run(name, func(t *testing.T) {
			n, err := Parse([]byte(name))
			if err != nil {
				t.Fatalf("Parse(%q): %v", name, err)
			}
			if n.String() != string(n.Raw()) {
				t.Errorf("String() = %q, Raw() = %q; they must not diverge", n.String(), n.Raw())
			}
			if n.String() != name {
				t.Errorf("String() = %q, want the received bytes %q", n.String(), name)
			}
		})
	}
}
