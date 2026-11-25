package suite

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"hash"
	"testing"

	"golang.zx2c4.com/wireguard/handshakename"
	"golang.zx2c4.com/wireguard/initialstate"
)

// This package contains no cryptography, so its tests use stubs. The real
// implementations are exercised in suitestd and suitewolf, which cannot be
// imported here: they import this package, and a test binary holding that pair
// would be an import cycle.

const (
	legacyName  = "Noise_IKpsk2_SECP256R1_AesGcm_SHA256"
	dynamicName = ":P-256:HKDF-SHA-256:AEAD_AES_256_GCM"
	identifier  = "WolfGuard v1 info@wolfssl.com"
)

// stubKEX is a key exchange that does no cryptography.
type stubKEX struct{ pubLen, privLen int }

var _ KEX = stubKEX{}

func (k stubKEX) PublicKeySize() int  { return k.pubLen }
func (k stubKEX) PrivateKeySize() int { return k.privLen }

func (k stubKEX) GenerateKey() (priv, pub []byte, err error) {
	return bytes.Repeat([]byte{1}, k.privLen), bytes.Repeat([]byte{2}, k.pubLen), nil
}

func (k stubKEX) PublicKey(priv []byte) ([]byte, error) {
	return bytes.Repeat([]byte{2}, k.pubLen), nil
}

func (k stubKEX) SharedSecret(priv, peerPub []byte) ([]byte, error) {
	return bytes.Repeat([]byte{3}, 32), nil
}

// stubHash is a fixed-size hash that ignores its input, which is enough to
// exercise dispatch and sizing.
type stubHash struct{ n int }

func (h stubHash) Write(p []byte) (int, error) { return len(p), nil }
func (h stubHash) Sum(b []byte) []byte         { return append(b, make([]byte, h.n)...) }
func (h stubHash) Reset()                      {}
func (h stubHash) Size() int                   { return h.n }
func (h stubHash) BlockSize() int              { return 64 }

type stubAEAD struct{ overhead int }

func (a stubAEAD) NonceSize() int { return 12 }
func (a stubAEAD) Overhead() int  { return a.overhead }

func (a stubAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	return append(append(dst, plaintext...), make([]byte, a.overhead)...)
}

func (a stubAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(ciphertext) < a.overhead {
		return nil, errors.New("short ciphertext")
	}
	return append(dst, ciphertext[:len(ciphertext)-a.overhead]...), nil
}

// clearTables empties the dispatch tables, which is also the state a build that
// registers no backend starts in.
func clearTables() {
	tablesMu.Lock()
	defer tablesMu.Unlock()
	kexByName = map[string]KEX{}
	hashByName = map[string]func() hash.Hash{}
	aeadByName = map[string]aeadSpec{}
}

// registerStubs installs a complete stub backend for one test and clears it
// afterwards, so registrations cannot leak between tests.
func registerStubs(t *testing.T) {
	t.Helper()
	clearTables()
	RegisterKEX("P-256", stubKEX{pubLen: 65, privLen: 32})
	RegisterHash("HKDF-SHA-256", func() hash.Hash { return stubHash{n: 32} })
	RegisterAEAD("AEAD_AES_256_GCM", 32, func(key []byte) (cipher.AEAD, error) {
		return stubAEAD{overhead: 16}, nil
	})
	t.Cleanup(clearTables)
}

// TestNoBackendResolvesNothing is the property that lets wolfGuard ship without
// non-approved algorithms rather than merely decline to use them.
//
// With no backend registered, every name is refused. A build that registers
// only approved primitives cannot be talked into a non-approved one, because
// the implementation is not in the binary: the name is unreachable, not
// reachable-but-declined.
func TestNoBackendResolvesNothing(t *testing.T) {
	clearTables()
	t.Cleanup(clearTables)

	for _, name := range []string{"X25519", "P-256", "P-384"} {
		if _, err := Resolve(name, "HKDF-SHA-256", "AEAD_AES_256_GCM"); !errors.Is(err, ErrUnknownKEX) {
			t.Errorf("Resolve(%q) error = %v, want %v", name, err, ErrUnknownKEX)
		}
	}

	r := NewRegistry()
	for _, n := range []string{
		":X25519:HKDF-BLAKE2S-256:AEAD_CHACHA20_POLY1305",
		":P-256:HKDF-SHA-256:AEAD_AES_256_GCM",
	} {
		if _, err := r.Accept([]byte(n), []byte(identifier)); err == nil {
			t.Errorf("Accept(%q) succeeded with no backend registered", n)
		}
	}
	if r.Len() != 0 {
		t.Errorf("registry holds %d suites with no backend registered", r.Len())
	}
}

// TestPartialBackendRefusesTheRest is the realistic FIPS shape: the approved
// primitives are registered and nothing else is, so a peer naming a
// non-approved one is refused by name.
func TestPartialBackendRefusesTheRest(t *testing.T) {
	registerStubs(t)

	if _, err := Resolve("P-256", "HKDF-SHA-256", "AEAD_AES_256_GCM"); err != nil {
		t.Fatalf("the registered suite does not resolve: %v", err)
	}

	tests := []struct {
		name           string
		kex, kdf, aead string
		want           error
	}{
		{name: "non-approved key exchange", kex: "X25519", kdf: "HKDF-SHA-256", aead: "AEAD_AES_256_GCM", want: ErrUnknownKEX},
		{name: "non-approved hash", kex: "P-256", kdf: "HKDF-BLAKE2S-256", aead: "AEAD_AES_256_GCM", want: ErrUnknownKDF},
		{name: "non-approved aead", kex: "P-256", kdf: "HKDF-SHA-256", aead: "AEAD_CHACHA20_POLY1305", want: ErrUnknownAEAD},
		{name: "weaker aes", kex: "P-256", kdf: "HKDF-SHA-256", aead: "AEAD_AES_128_GCM", want: ErrUnknownAEAD},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Resolve(tt.kex, tt.kdf, tt.aead); !errors.Is(err, tt.want) {
				t.Errorf("Resolve error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestResolveRejectsUnknownPrimitives(t *testing.T) {
	registerStubs(t)

	tests := []struct {
		name           string
		kex, kdf, aead string
		want           error
	}{
		{name: "unknown kex", kex: "P-521", kdf: "HKDF-SHA-256", aead: "AEAD_AES_256_GCM", want: ErrUnknownKEX},
		{name: "unknown kdf", kex: "P-256", kdf: "HKDF-SHA3-256", aead: "AEAD_AES_256_GCM", want: ErrUnknownKDF},
		{name: "unknown aead", kex: "P-256", kdf: "HKDF-SHA-256", aead: "AEAD_AES_256_CCM", want: ErrUnknownAEAD},
		{
			name: "legacy vocabulary is not the registry vocabulary",
			kex:  "SECP256R1", kdf: "SHA256", aead: "AesGcm", want: ErrUnknownKEX,
		},
		{name: "empty", kex: "", kdf: "", aead: "", want: ErrUnknownKEX},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := Resolve(tt.kex, tt.kdf, tt.aead)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Resolve error = %v, want %v", err, tt.want)
			}
			if s != nil {
				t.Error("Resolve returned a suite alongside an error")
			}
		})
	}
}

func TestAcceptRejectsMalformedName(t *testing.T) {
	registerStubs(t)
	r := NewRegistry()

	if _, err := r.Accept([]byte(legacyName), []byte(identifier)); !errors.Is(err, handshakename.ErrNoLead) {
		t.Errorf("Accept of a legacy name error = %v, want %v", err, handshakename.ErrNoLead)
	}
	if _, err := r.Accept([]byte(":P-256:HKDF-SHA-256"), []byte(identifier)); !errors.Is(err, handshakename.ErrFieldCount) {
		t.Errorf("Accept of a two-field name error = %v, want %v", err, handshakename.ErrFieldCount)
	}
	if r.Len() != 0 {
		t.Errorf("failed Accepts stored %d suites, want 0", r.Len())
	}
}

// TestAcceptAndLookup covers the registry mechanism: a dynamic name resolves,
// is found by name, carries its initial state, and a name never accepted is
// absent.
func TestAcceptAndLookup(t *testing.T) {
	registerStubs(t)
	r := NewRegistry()

	s, err := r.Accept([]byte(dynamicName), []byte(identifier))
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if got := string(s.Name()); got != dynamicName {
		t.Errorf("Name() = %q, want %q", got, dynamicName)
	}
	if s.KEX.PublicKeySize() != 65 {
		t.Errorf("PublicKeySize = %d, want the stub's 65", s.KEX.PublicKeySize())
	}
	if len(s.State.ChainKey) != 32 {
		t.Errorf("ChainKey is %d bytes, want the stub hash's 32", len(s.State.ChainKey))
	}

	found, ok := r.Lookup([]byte(dynamicName))
	if !ok || found != s {
		t.Error("Lookup did not return the accepted suite")
	}
	if _, ok := r.Lookup([]byte(":P-384:HKDF-SHA-256:AEAD_AES_256_GCM")); ok {
		t.Error("Lookup reported a hit for a suite never accepted")
	}
	if r.Len() != 1 {
		t.Errorf("registry holds %d suites, want 1", r.Len())
	}
}

func TestAcceptLegacyStatesItsPrimitives(t *testing.T) {
	registerStubs(t)
	r := NewRegistry()

	s, err := r.AcceptLegacy([]byte(legacyName), "P-256", "HKDF-SHA-256", "AEAD_AES_256_GCM", []byte(identifier))
	if err != nil {
		t.Fatalf("AcceptLegacy: %v", err)
	}
	if got := string(s.Name()); got != legacyName {
		t.Errorf("Name() = %q, want %q", got, legacyName)
	}

	// The legacy spellings must not resolve, which is why a legacy suite's
	// primitives have to be stated rather than parsed out of its name.
	if _, err := r.AcceptLegacy([]byte(legacyName), "SECP256R1", "SHA256", "AesGcm", []byte(identifier)); !errors.Is(err, ErrUnknownKEX) {
		t.Errorf("AcceptLegacy with legacy spellings error = %v, want %v", err, ErrUnknownKEX)
	}
}

func TestAcceptRejectsEmptyIdentifier(t *testing.T) {
	registerStubs(t)
	r := NewRegistry()

	if _, err := r.Accept([]byte(dynamicName), nil); !errors.Is(err, initialstate.ErrEmptyIdentifier) {
		t.Errorf("Accept with no identifier error = %v, want %v", err, initialstate.ErrEmptyIdentifier)
	}
	if r.Len() != 0 {
		t.Errorf("failed Accept stored %d suites, want 0", r.Len())
	}
	if _, ok := r.Lookup([]byte(dynamicName)); ok {
		t.Error("a failed Accept left the suite findable")
	}
}

// TestAEADKeyLengthGuardAppliesToEveryBackend checks that registration wraps
// whatever constructor it is given, so no backend can be driven with a key
// length its name does not describe.
func TestAEADKeyLengthGuardAppliesToEveryBackend(t *testing.T) {
	clearTables()
	t.Cleanup(clearTables)
	RegisterKEX("P-256", stubKEX{pubLen: 65, privLen: 32})
	RegisterHash("HKDF-SHA-256", func() hash.Hash { return stubHash{n: 32} })

	// A constructor that would accept any key length at all.
	RegisterAEAD("AEAD_AES_256_GCM", 32, func(key []byte) (cipher.AEAD, error) {
		return stubAEAD{overhead: 16}, nil
	})

	s, err := Resolve("P-256", "HKDF-SHA-256", "AEAD_AES_256_GCM")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := s.NewAEAD(make([]byte, 32)); err != nil {
		t.Errorf("the declared key length was rejected: %v", err)
	}
	for _, n := range []int{0, 16, 24, 33} {
		if _, err := s.NewAEAD(make([]byte, n)); !errors.Is(err, ErrKeySize) {
			t.Errorf("a %d byte key gave %v, want %v", n, err, ErrKeySize)
		}
	}
}
