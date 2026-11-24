package suite

import (
	"bytes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"testing"

	"golang.zx2c4.com/wireguard/handshakename"
	"golang.zx2c4.com/wireguard/initialstate"
)

// Every vector below was produced by python-cryptography 41.0.7, an
// OpenSSL-backed implementation independent of Go's, with this script:
// scratchpad/genvec.py. They exist to catch mis-wiring, a suite resolving to
// AES-128 where it named AES-256, or to the wrong curve, which a round-trip
// against our own code could never detect.
const (
	x25519PrivA  = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	x25519PubA   = "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c"
	x25519PrivB  = "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"
	x25519PubB   = "5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b"
	x25519Shared = "a84dc7c3c8f058b1b2dc4cd1e9b5dc0a7987f88b6a9564cde3391fc421159e77"

	p256PrivA  = "1111111111111111111111111111111111111111111111111111111111111111"
	p256PubA   = "040217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c65306e5794"
	p256PrivB  = "2222222222222222222222222222222222222222222222222222222222222222"
	p256PubB   = "04d65a93977caa3d1b081852ff57a79e465f1660577304baead505dd3a48589cf350185e895372df6221ea3a137557e473fddb6755f05bd507c3c533fce9c91285"
	p256Shared = "ccfc261f58193c98ca4ad4a53bbac6f0ee29bc4d48438090446908622ca79af6"

	aeadKey   = "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc"
	aeadNonce = "a0a1a2a3a4a5a6a7a8a9aaab"
	aeadPT    = "776f6c664775617264206e616d65642d616c676f2070726f746f74797065"
	aeadAAD   = "6173736f6369617465642d64617461"

	aesGCMCT    = "0ceb1f6faa08cea770a64431477a886d7a425801b097900b51976d2a525330c635793c0f754b157590acd0d7f7a8"
	chachaPolCT = "391216b3456c7537a00b9cf01e1da9fb42ef2062275e087d23e56b53c77a9fb9b749eef8ce076d8fc1ceb383cbbb"
)

// The two suites that exist today, as dynamic names.
const (
	fipsName  = ":P-256:HKDF-SHA-256:AEAD_AES_256_GCM"
	stockName = ":X25519:HKDF-BLAKE2S-256:AEAD_CHACHA20_POLY1305"

	legacyFIPSName = "Noise_IKpsk2_SECP256R1_AesGcm_SHA256"
	wolfGuardID    = "WolfGuard v1 info@wolfssl.com"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decoding vector %q: %v", s, err)
	}
	return b
}

// TestKEXAgreesWithIndependentImplementation checks each curve against a shared
// secret computed by python-cryptography from the same key material.
func TestKEXAgreesWithIndependentImplementation(t *testing.T) {
	tests := []struct {
		name                    string
		kex                     string
		privA, pubB, wantShared string
	}{
		{name: "X25519", kex: "X25519", privA: x25519PrivA, pubB: x25519PubB, wantShared: x25519Shared},
		{name: "P-256", kex: "P-256", privA: p256PrivA, pubB: p256PubB, wantShared: p256Shared},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, ok := kexByName[tt.kex]
			if !ok {
				t.Fatalf("%q is not in the dispatch table", tt.kex)
			}

			got, err := k.SharedSecret(unhex(t, tt.privA), unhex(t, tt.pubB))
			if err != nil {
				t.Fatalf("SharedSecret: %v", err)
			}
			if hex.EncodeToString(got) != tt.wantShared {
				t.Errorf("shared secret = %x, want %s", got, tt.wantShared)
			}
		})
	}
}

// TestKEXPublicKeyDerivesCorrectly confirms the private keys in the vectors
// really correspond to the recorded public keys, so the table is wired to the
// curve the name says and not merely to something self-consistent.
func TestKEXPublicKeyDerivesCorrectly(t *testing.T) {
	tests := []struct {
		name, kex, priv, wantPub string
	}{
		{name: "X25519 A", kex: "X25519", priv: x25519PrivA, wantPub: x25519PubA},
		{name: "X25519 B", kex: "X25519", priv: x25519PrivB, wantPub: x25519PubB},
		{name: "P-256 A", kex: "P-256", priv: p256PrivA, wantPub: p256PubA},
		{name: "P-256 B", kex: "P-256", priv: p256PrivB, wantPub: p256PubB},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := kexByName[tt.kex]
			got, err := k.PublicKey(unhex(t, tt.priv))
			if err != nil {
				t.Fatalf("PublicKey: %v", err)
			}
			if hex.EncodeToString(got) != tt.wantPub {
				t.Errorf("public key = %x, want %s", got, tt.wantPub)
			}
		})
	}
}

// TestKEXSizesMatchGeneratedKeys guards the constants the wire layout depends
// on. A wrong PublicKeySize would size a message field wrongly, so it is
// checked against a key the curve actually produces rather than trusted.
func TestKEXSizesMatchGeneratedKeys(t *testing.T) {
	for name, k := range kexByName {
		t.Run(name, func(t *testing.T) {
			priv, pub, err := k.GenerateKey()
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			if got := len(pub); got != k.PublicKeySize() {
				t.Errorf("PublicKeySize() = %d, GenerateKey produced %d", k.PublicKeySize(), got)
			}
			if got := len(priv); got != k.PrivateKeySize() {
				t.Errorf("PrivateKeySize() = %d, GenerateKey produced %d", k.PrivateKeySize(), got)
			}
		})
	}
}

// TestAEADAgreesWithIndependentImplementation seals the same plaintext under
// the same key, nonce and AAD and compares against python-cryptography's
// ciphertext and tag.
func TestAEADAgreesWithIndependentImplementation(t *testing.T) {
	tests := []struct {
		name, aead, wantCT string
		wantKeySize        int
	}{
		{name: "AES-256-GCM", aead: "AEAD_AES_256_GCM", wantCT: aesGCMCT, wantKeySize: 32},
		{name: "ChaCha20-Poly1305", aead: "AEAD_CHACHA20_POLY1305", wantCT: chachaPolCT, wantKeySize: 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, ok := aeadByName[tt.aead]
			if !ok {
				t.Fatalf("%q is not in the dispatch table", tt.aead)
			}
			if spec.keySize != tt.wantKeySize {
				t.Errorf("keySize = %d, want %d", spec.keySize, tt.wantKeySize)
			}

			a, err := spec.new(unhex(t, aeadKey))
			if err != nil {
				t.Fatalf("constructing AEAD: %v", err)
			}
			got := a.Seal(nil, unhex(t, aeadNonce), unhex(t, aeadPT), unhex(t, aeadAAD))
			if hex.EncodeToString(got) != tt.wantCT {
				t.Errorf("Seal = %x\n want %s", got, tt.wantCT)
			}
		})
	}
}

// TestAEADEnforcesItsKeyLength is the mis-wiring check that matters most.
// aes.NewCipher picks the AES variant from the key length, so without an exact
// check a suite runs a different cipher than the name hashed into its chaining
// key: a short key under AEAD_AES_256_GCM is a silent downgrade to AES-128, and
// a long key under AEAD_AES_128_GCM is a silent upgrade to AES-256. Both are
// wrong, because the name is what both peers agreed on.
func TestAEADEnforcesItsKeyLength(t *testing.T) {
	key32 := unhex(t, aeadKey)
	key16 := key32[:16]

	tests := []struct {
		name     string
		aead     string
		keySize  int
		tooLong  []byte
		tooShort []byte
	}{
		{name: "AES-128-GCM", aead: "AEAD_AES_128_GCM", keySize: 16, tooLong: key32},
		{name: "AES-256-GCM", aead: "AEAD_AES_256_GCM", keySize: 32, tooShort: key16},
		{name: "ChaCha20-Poly1305", aead: "AEAD_CHACHA20_POLY1305", keySize: 32, tooShort: key16},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := aeadByName[tt.aead]
			if spec.keySize != tt.keySize {
				t.Fatalf("keySize = %d, want %d", spec.keySize, tt.keySize)
			}

			// The declared length must work.
			if _, err := spec.new(key32[:tt.keySize]); err != nil {
				t.Errorf("rejected a correct %d byte key: %v", tt.keySize, err)
			}
			for label, bad := range map[string][]byte{"too long": tt.tooLong, "too short": tt.tooShort} {
				if bad == nil {
					continue
				}
				if _, err := spec.new(bad); !errors.Is(err, ErrKeySize) {
					t.Errorf("%s key (%d bytes) error = %v, want %v", label, len(bad), err, ErrKeySize)
				}
			}
		})
	}
}

func TestResolveRejectsUnknownPrimitives(t *testing.T) {
	tests := []struct {
		name           string
		kex, kdf, aead string
		want           error
	}{
		{name: "unknown kex", kex: "P-521", kdf: "HKDF-SHA-256", aead: "AEAD_AES_256_GCM", want: ErrUnknownKEX},
		{name: "unknown kdf", kex: "P-256", kdf: "HKDF-SHA3-256", aead: "AEAD_AES_256_GCM", want: ErrUnknownKDF},
		{name: "unknown aead", kex: "P-256", kdf: "HKDF-SHA-256", aead: "AEAD_AES_256_CCM", want: ErrUnknownAEAD},
		{name: "legacy vocabulary is not the registry vocabulary",
			kex: "SECP256R1", kdf: "SHA256", aead: "AesGcm", want: ErrUnknownKEX},
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

func TestAcceptResolvesDynamicName(t *testing.T) {
	tests := []struct {
		name            string
		hsName          string
		wantPubKeySize  int
		wantAEADKeySize int
		wantHashSize    int
	}{
		{name: "fips suite", hsName: fipsName, wantPubKeySize: 65, wantAEADKeySize: 32, wantHashSize: 32},
		{name: "stock suite", hsName: stockName, wantPubKeySize: 32, wantAEADKeySize: 32, wantHashSize: 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRegistry()
			s, err := r.Accept([]byte(tt.hsName), []byte(wolfGuardID))
			if err != nil {
				t.Fatalf("Accept(%q): %v", tt.hsName, err)
			}
			if s.KEX.PublicKeySize() != tt.wantPubKeySize {
				t.Errorf("PublicKeySize = %d, want %d", s.KEX.PublicKeySize(), tt.wantPubKeySize)
			}
			if s.AEADKeySize != tt.wantAEADKeySize {
				t.Errorf("AEADKeySize = %d, want %d", s.AEADKeySize, tt.wantAEADKeySize)
			}
			if got := s.NewHash().Size(); got != tt.wantHashSize {
				t.Errorf("hash size = %d, want %d", got, tt.wantHashSize)
			}
			if !bytes.Equal(s.Name(), []byte(tt.hsName)) {
				t.Errorf("Name() = %q, want %q", s.Name(), tt.hsName)
			}
			if len(s.State.ChainKey) != tt.wantHashSize {
				t.Errorf("ChainKey is %d bytes, want %d", len(s.State.ChainKey), tt.wantHashSize)
			}
		})
	}
}

// TestAcceptLegacyReproducesDeployedState is the interoperability check: a
// legacy suite registered through AcceptLegacy must derive exactly the chaining
// key and hash that deployed wolfGuard peers compute today. Both expected
// values were computed with coreutils, not by this code.
func TestAcceptLegacyReproducesDeployedState(t *testing.T) {
	r := NewRegistry()
	s, err := r.AcceptLegacy([]byte(legacyFIPSName), "P-256", "HKDF-SHA-256", "AEAD_AES_256_GCM", []byte(wolfGuardID))
	if err != nil {
		t.Fatalf("AcceptLegacy: %v", err)
	}

	const (
		wantChainKey = "082dafe0b19fee706a69f2b95ca6e1369fabd5365f0e91622574735b7f24be48"
		wantHash     = "05b688c3b96ec779407780baecbf198e39a13d2c427445ef2839cb5e211b6a00"
	)
	if got := hex.EncodeToString(s.State.ChainKey); got != wantChainKey {
		t.Errorf("ChainKey = %s, want %s (breaks every deployed peer)", got, wantChainKey)
	}
	if got := hex.EncodeToString(s.State.Hash); got != wantHash {
		t.Errorf("Hash = %s, want %s (breaks every deployed peer)", got, wantHash)
	}
}

// TestRegistryHoldsTwoLiveSuites is the migration case: both suites accepted at
// once, each found by its own name, with distinct initial state.
func TestRegistryHoldsTwoLiveSuites(t *testing.T) {
	r := NewRegistry()
	for _, n := range []string{fipsName, stockName} {
		if _, err := r.Accept([]byte(n), []byte(wolfGuardID)); err != nil {
			t.Fatalf("Accept(%q): %v", n, err)
		}
	}
	if r.Len() != 2 {
		t.Fatalf("registry holds %d suites, want 2", r.Len())
	}

	a, ok := r.Lookup([]byte(fipsName))
	if !ok {
		t.Fatal("fips suite missing")
	}
	b, ok := r.Lookup([]byte(stockName))
	if !ok {
		t.Fatal("stock suite missing")
	}
	if bytes.Equal(a.State.ChainKey, b.State.ChainKey) {
		t.Error("two live suites share a chaining key")
	}
	if a.KEX.PublicKeySize() == b.KEX.PublicKeySize() {
		t.Error("expected the two suites to differ in public key size, which is what forces runtime sizing")
	}

	if _, ok := r.Lookup([]byte(":P-384:HKDF-SHA-384:AEAD_AES_256_GCM")); ok {
		t.Error("Lookup reported a hit for a suite never accepted")
	}
}

func TestAcceptRejectsMalformedName(t *testing.T) {
	r := NewRegistry()
	if _, err := r.Accept([]byte(legacyFIPSName), []byte(wolfGuardID)); !errors.Is(err, handshakename.ErrNoLead) {
		t.Errorf("Accept of a legacy name error = %v, want %v", err, handshakename.ErrNoLead)
	}
	if _, err := r.Accept([]byte(":P-256:HKDF-SHA-256"), []byte(wolfGuardID)); !errors.Is(err, handshakename.ErrFieldCount) {
		t.Errorf("Accept of a two-field name error = %v, want %v", err, handshakename.ErrFieldCount)
	}
	if r.Len() != 0 {
		t.Errorf("failed Accepts stored %d suites, want 0", r.Len())
	}
}

func TestAcceptRejectsUnimplementedPrimitive(t *testing.T) {
	r := NewRegistry()
	_, err := r.Accept([]byte(":X25519+ML-KEM-768:HKDF-SHA-256:AEAD_AES_256_GCM"), []byte(wolfGuardID))
	if !errors.Is(err, ErrUnknownKEX) {
		t.Errorf("Accept of an unimplemented hybrid error = %v, want %v", err, ErrUnknownKEX)
	}
	if r.Len() != 0 {
		t.Errorf("failed Accept stored %d suites, want 0", r.Len())
	}
}

func TestAcceptLegacyRejectsUnknownPrimitive(t *testing.T) {
	r := NewRegistry()
	// The legacy vocabulary is exactly what must not be passed through here.
	_, err := r.AcceptLegacy([]byte(legacyFIPSName), "SECP256R1", "SHA256", "AesGcm", []byte(wolfGuardID))
	if !errors.Is(err, ErrUnknownKEX) {
		t.Errorf("AcceptLegacy error = %v, want %v", err, ErrUnknownKEX)
	}
	if r.Len() != 0 {
		t.Errorf("failed AcceptLegacy stored %d suites, want 0", r.Len())
	}
}

// TestAcceptRejectsEmptyIdentifier covers the derivation failing after the name
// resolves. The identifier is configuration, so an empty one is a local wiring
// mistake and must not produce a half-registered suite.
func TestAcceptRejectsEmptyIdentifier(t *testing.T) {
	r := NewRegistry()
	if _, err := r.Accept([]byte(fipsName), nil); !errors.Is(err, initialstate.ErrEmptyIdentifier) {
		t.Errorf("Accept with no identifier error = %v, want %v", err, initialstate.ErrEmptyIdentifier)
	}
	if r.Len() != 0 {
		t.Errorf("failed Accept stored %d suites, want 0", r.Len())
	}
	if _, ok := r.Lookup([]byte(fipsName)); ok {
		t.Error("a failed Accept left the suite findable")
	}
}

// stubKEX stands in for a wolfCrypt-backed implementation: it satisfies KEX
// without crypto/ecdh, which is the whole point of the interface.
type stubKEX struct {
	pubLen, privLen int
	calls           *int
}

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
	*k.calls++
	return bytes.Repeat([]byte{3}, 32), nil
}

// TestRegisterKEXSubstitutesBackend is the substitutability check: a foreign
// KEX implementation registered under a canonical name is the one a resolved
// suite uses, with no change to Resolve or Registry. This is the path a FIPS
// build takes to route public names to wolfCrypt.
func TestRegisterKEXSubstitutesBackend(t *testing.T) {
	const name = "P-256"

	tablesMu.RLock()
	original := kexByName[name]
	tablesMu.RUnlock()
	t.Cleanup(func() { RegisterKEX(name, original) })

	calls := 0
	RegisterKEX(name, stubKEX{pubLen: 7, privLen: 5, calls: &calls})

	s, err := Resolve("P-256", "HKDF-SHA-256", "AEAD_AES_256_GCM")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if s.KEX.PublicKeySize() != 7 || s.KEX.PrivateKeySize() != 5 {
		t.Errorf("resolved sizes %d/%d, want the stub's 7/5",
			s.KEX.PublicKeySize(), s.KEX.PrivateKeySize())
	}
	if _, err := s.KEX.SharedSecret(nil, nil); err != nil {
		t.Fatalf("stub SharedSecret: %v", err)
	}
	if calls != 1 {
		t.Errorf("stub SharedSecret called %d times, want 1", calls)
	}

	// The real backend must come back once the stub is unregistered.
	RegisterKEX(name, original)
	s2, err := Resolve("P-256", "HKDF-SHA-256", "AEAD_AES_256_GCM")
	if err != nil {
		t.Fatalf("Resolve after restore: %v", err)
	}
	if s2.KEX.PublicKeySize() != 65 {
		t.Errorf("restored PublicKeySize = %d, want 65", s2.KEX.PublicKeySize())
	}
}

// TestKEXRejectsMalformedKeys covers the pre-authentication rejection path: a
// peer's ephemeral arrives from the wire and may be anything at all.
//
// The two curves legitimately differ on what "malformed" means, and the test
// records that rather than pretending they agree. X25519 has no point
// validation by design (RFC 7748), so every 32-byte string is a valid public
// key and an arbitrary one is accepted; what it does reject is a low-order
// point, which yields an all-zero shared secret. P-256 validates that a point
// is on the curve, so garbage is rejected outright.
func TestKEXRejectsMalformedKeys(t *testing.T) {
	tests := []struct {
		name string
		// allOnesPubRejected is whether an all-ones public key is refused.
		allOnesPubRejected bool
		// zeroPubRejected is whether an all-zero public key is refused.
		zeroPubRejected bool
	}{
		{name: "X25519", allOnesPubRejected: false, zeroPubRejected: true},
		{name: "P-256", allOnesPubRejected: true, zeroPubRejected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tablesMu.RLock()
			k := kexByName[tt.name]
			tablesMu.RUnlock()

			goodPriv, goodPub, err := k.GenerateKey()
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}

			// Length errors are rejected by both.
			if _, err := k.SharedSecret(goodPriv[:len(goodPriv)-1], goodPub); err == nil {
				t.Error("SharedSecret accepted a truncated private key")
			}
			if _, err := k.SharedSecret(goodPriv, goodPub[:len(goodPub)-1]); err == nil {
				t.Error("SharedSecret accepted a truncated peer public key")
			}
			if _, err := k.PublicKey(nil); err == nil {
				t.Error("PublicKey accepted a nil private key")
			}

			// A correct pair must still work, so the checks above are not
			// passing for the wrong reason.
			if _, err := k.SharedSecret(goodPriv, goodPub); err != nil {
				t.Errorf("SharedSecret rejected a valid pair: %v", err)
			}

			_, allOnesErr := k.SharedSecret(goodPriv, bytes.Repeat([]byte{0xff}, len(goodPub)))
			if got := allOnesErr != nil; got != tt.allOnesPubRejected {
				t.Errorf("all-ones public key rejected = %v, want %v (err %v)", got, tt.allOnesPubRejected, allOnesErr)
			}

			_, zeroErr := k.SharedSecret(goodPriv, make([]byte, len(goodPub)))
			if got := zeroErr != nil; got != tt.zeroPubRejected {
				t.Errorf("all-zero public key rejected = %v, want %v (err %v)", got, tt.zeroPubRejected, zeroErr)
			}
		})
	}
}

// TestRegisterHashAndAEADSubstituteBackends mirrors the KEX case for the other
// two primitives, because a FIPS build has to route all three to wolfCrypt, not
// just the key exchange.
func TestRegisterHashAndAEADSubstituteBackends(t *testing.T) {
	const (
		kdfName  = "HKDF-SHA-256"
		aeadName = "AEAD_AES_256_GCM"
	)

	tablesMu.RLock()
	origHash := hashByName[kdfName]
	origAEAD := aeadByName[aeadName]
	tablesMu.RUnlock()
	t.Cleanup(func() {
		tablesMu.Lock()
		hashByName[kdfName] = origHash
		aeadByName[aeadName] = origAEAD
		tablesMu.Unlock()
	})

	// A stand-in hash with a different digest size proves the suite uses the
	// registered constructor rather than a hardwired one.
	RegisterHash(kdfName, sha512.New)
	// A stand-in AEAD that refuses to construct proves the same for the AEAD,
	// and that the key-length guard still wraps a registered implementation.
	sentinel := errors.New("stand-in aead")
	RegisterAEAD(aeadName, 32, func(key []byte) (cipher.AEAD, error) { return nil, sentinel })

	s, err := Resolve("P-256", kdfName, aeadName)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := s.NewHash().Size(); got != sha512.Size {
		t.Errorf("hash size = %d, want the registered %d", got, sha512.Size)
	}
	if _, err := s.NewAEAD(make([]byte, 32)); !errors.Is(err, sentinel) {
		t.Errorf("AEAD error = %v, want the registered %v", err, sentinel)
	}
	// The length guard must still apply to a registered implementation.
	if _, err := s.NewAEAD(make([]byte, 16)); !errors.Is(err, ErrKeySize) {
		t.Errorf("short key error = %v, want %v", err, ErrKeySize)
	}
}
