package initialstate

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"sync"
	"testing"

	"golang.org/x/crypto/blake2s"
)

// Identifiers as deployed. Both are per-peer configuration, not wire data.
const (
	wolfGuardID = "WolfGuard v1 info@wolfssl.com"
	wireGuardID = "WireGuard v1 zx2c4 Jason@zx2c4.com"
)

// Handshake names: the two compiled-in constants in the field, and one dynamic
// name carried on the wire.
const (
	legacyFIPSName  = "Noise_IKpsk2_SECP256R1_AesGcm_SHA256"
	legacyStockName = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	dynamicFIPSName = ":P-256:HKDF-SHA-256:AEAD_AES_256_GCM"
)

func newSHA256() hash.Hash { return sha256.New() }

func newBLAKE2s() hash.Hash {
	h, err := blake2s.New256(nil)
	if err != nil {
		panic("blake2s.New256 with a nil key cannot fail: " + err.Error())
	}
	return h
}

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decoding oracle value %q: %v", s, err)
	}
	return b
}

// TestDeriveMatchesExternalOracle is the compatibility proof. Every expected
// value was computed outside Go, so this checks the derivation against the
// protocol rather than against itself:
//
//	ck=$(printf '%s' "$NAME" | sha256sum | cut -d' ' -f1)
//	{ printf '%s' "$ck" | xxd -r -p; printf '%s' "$ID"; } | sha256sum
//
// and with 'openssl dgst -blake2s256 -r' in place of sha256sum for the BLAKE2s
// case. The BLAKE2s row therefore also cross-validates two independent
// implementations, OpenSSL's and x/crypto's.
//
// The legacy rows are the values deployed wolfGuard and stock WireGuard peers
// actually use. If this test fails, the change breaks interoperability with
// every peer in the field.
func TestDeriveMatchesExternalOracle(t *testing.T) {
	tests := []struct {
		name         string
		newHash      func() hash.Hash
		hsName       string
		identifier   string
		wantChainKey string
		wantHash     string
	}{
		{
			name:         "deployed wolfGuard FIPS, SHA-256",
			newHash:      newSHA256,
			hsName:       legacyFIPSName,
			identifier:   wolfGuardID,
			wantChainKey: "082dafe0b19fee706a69f2b95ca6e1369fabd5365f0e91622574735b7f24be48",
			wantHash:     "05b688c3b96ec779407780baecbf198e39a13d2c427445ef2839cb5e211b6a00",
		},
		{
			name:         "deployed stock WireGuard, BLAKE2s-256",
			newHash:      newBLAKE2s,
			hsName:       legacyStockName,
			identifier:   wireGuardID,
			wantChainKey: "60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36",
			wantHash:     "2211b361081ac566691243db458ad5322d9c6c662293e8b70ee19c65ba079ef3",
		},
		{
			name:         "dynamic FIPS name, SHA-256",
			newHash:      newSHA256,
			hsName:       dynamicFIPSName,
			identifier:   wolfGuardID,
			wantChainKey: "dbcd34997320f3f623e325b2b8c4bd902d7f70b7e650796c2031c54a3294ecac",
			wantHash:     "6dd3756245b01c8dbe52a11fa04b857d3fae3eb0b6fa70b3df44f6093f91376d",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st, err := Derive(tt.newHash, []byte(tt.hsName), []byte(tt.identifier))
			if err != nil {
				t.Fatalf("Derive: %v", err)
			}
			if got := hex.EncodeToString(st.ChainKey); got != tt.wantChainKey {
				t.Errorf("ChainKey = %s, want %s", got, tt.wantChainKey)
			}
			if got := hex.EncodeToString(st.Hash); got != tt.wantHash {
				t.Errorf("Hash = %s, want %s", got, tt.wantHash)
			}
		})
	}
}

// TestHashIsNotHardwired guards the agnosticism the package exists for: the
// same name under two different hashes must produce different state, so nothing
// has quietly hardwired SHA-256.
func TestHashIsNotHardwired(t *testing.T) {
	sha, err := Derive(newSHA256, []byte(legacyFIPSName), []byte(wolfGuardID))
	if err != nil {
		t.Fatalf("Derive with SHA-256: %v", err)
	}
	b2, err := Derive(newBLAKE2s, []byte(legacyFIPSName), []byte(wolfGuardID))
	if err != nil {
		t.Fatalf("Derive with BLAKE2s: %v", err)
	}
	if hex.EncodeToString(sha.ChainKey) == hex.EncodeToString(b2.ChainKey) {
		t.Error("SHA-256 and BLAKE2s produced the same chaining key; the hash is hardwired")
	}
}

// TestDistinctInputsDeriveDistinctState is the domain-separation property.
// Suites, and the legacy and dynamic forms of one suite, must never share a
// chaining key, and changing only the identifier must still change the hash.
func TestDistinctInputsDeriveDistinctState(t *testing.T) {
	inputs := []struct{ name, id string }{
		{legacyFIPSName, wolfGuardID},
		{dynamicFIPSName, wolfGuardID},
		{legacyStockName, wolfGuardID},
		{legacyFIPSName, wireGuardID},
	}

	chainKeys := make(map[string]string, len(inputs))
	hashes := make(map[string]string, len(inputs))
	for _, in := range inputs {
		st, err := Derive(newSHA256, []byte(in.name), []byte(in.id))
		if err != nil {
			t.Fatalf("Derive(%q, %q): %v", in.name, in.id, err)
		}
		label := in.name + " / " + in.id

		hk := hex.EncodeToString(st.Hash)
		if prev, ok := hashes[hk]; ok {
			t.Errorf("%s and %s derive the same hash", prev, label)
		}
		hashes[hk] = label

		// The chaining key does not depend on the identifier, so the two rows
		// sharing a name are expected to collide there. Only flag a collision
		// between different names.
		ck := hex.EncodeToString(st.ChainKey)
		if prev, ok := chainKeys[ck]; ok && prev != in.name {
			t.Errorf("names %q and %q derive the same chaining key", prev, in.name)
		}
		chainKeys[ck] = in.name
	}
}

func TestDeriveRejects(t *testing.T) {
	tests := []struct {
		name       string
		newHash    func() hash.Hash
		hsName     string
		identifier string
		want       error
	}{
		{name: "nil hash constructor", newHash: nil, hsName: legacyFIPSName, identifier: wolfGuardID, want: ErrNoHash},
		{name: "empty name", newHash: newSHA256, hsName: "", identifier: wolfGuardID, want: ErrEmptyName},
		{name: "empty identifier", newHash: newSHA256, hsName: legacyFIPSName, identifier: "", want: ErrEmptyIdentifier},
		{
			name:    "constructor returns nil",
			newHash: func() hash.Hash { return nil },
			hsName:  legacyFIPSName, identifier: wolfGuardID,
			want: ErrNilHash,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st, err := Derive(tt.newHash, []byte(tt.hsName), []byte(tt.identifier))
			if !errors.Is(err, tt.want) {
				t.Fatalf("Derive error = %v, want %v", err, tt.want)
			}
			if st.ChainKey != nil || st.Hash != nil {
				t.Error("Derive returned usable state alongside an error")
			}
		})
	}
}

// TestDeriveDoesNotAliasAcrossCalls matters because each suite's state is held
// for the life of the device; two suites sharing a backing array would be a
// cross-suite key corruption.
func TestDeriveDoesNotAliasAcrossCalls(t *testing.T) {
	a, err := Derive(newSHA256, []byte(legacyFIPSName), []byte(wolfGuardID))
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	b, err := Derive(newSHA256, []byte(dynamicFIPSName), []byte(wolfGuardID))
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}

	before := hex.EncodeToString(b.ChainKey)
	for i := range a.ChainKey {
		a.ChainKey[i] = 0xff
	}
	for i := range a.Hash {
		a.Hash[i] = 0xff
	}
	if got := hex.EncodeToString(b.ChainKey); got != before {
		t.Errorf("overwriting one state changed another: %s became %s", before, got)
	}
}

func TestCacheRoundTrip(t *testing.T) {
	c := NewCache()
	if c.Len() != 0 {
		t.Fatalf("new cache holds %d suites, want 0", c.Len())
	}
	if _, ok := c.Get([]byte(legacyFIPSName)); ok {
		t.Error("empty cache reported a hit")
	}

	added, err := c.Add(newSHA256, []byte(legacyFIPSName), []byte(wolfGuardID))
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if c.Len() != 1 {
		t.Errorf("cache holds %d suites, want 1", c.Len())
	}

	got, ok := c.Get([]byte(legacyFIPSName))
	if !ok {
		t.Fatal("Get missed a suite that was just added")
	}
	if hex.EncodeToString(got.ChainKey) != hex.EncodeToString(added.ChainKey) {
		t.Error("Get returned different state than Add")
	}
	want := mustDecode(t, "082dafe0b19fee706a69f2b95ca6e1369fabd5365f0e91622574735b7f24be48")
	if hex.EncodeToString(got.ChainKey) != hex.EncodeToString(want) {
		t.Errorf("cached ChainKey = %x, want %x", got.ChainKey, want)
	}

	if _, ok := c.Get([]byte(dynamicFIPSName)); ok {
		t.Error("Get reported a hit for a suite never added")
	}
}

// TestCacheHoldsSuitesIndependently covers the migration case the cache exists
// for: two suites live at once, each resolvable by its own name.
func TestCacheHoldsSuitesIndependently(t *testing.T) {
	c := NewCache()
	for _, n := range []string{legacyFIPSName, dynamicFIPSName} {
		if _, err := c.Add(newSHA256, []byte(n), []byte(wolfGuardID)); err != nil {
			t.Fatalf("Add(%q): %v", n, err)
		}
	}
	if c.Len() != 2 {
		t.Fatalf("cache holds %d suites, want 2", c.Len())
	}

	legacy, ok := c.Get([]byte(legacyFIPSName))
	if !ok {
		t.Fatal("legacy suite missing")
	}
	dynamic, ok := c.Get([]byte(dynamicFIPSName))
	if !ok {
		t.Fatal("dynamic suite missing")
	}
	if hex.EncodeToString(legacy.ChainKey) == hex.EncodeToString(dynamic.ChainKey) {
		t.Error("two suites in one cache share a chaining key")
	}
}

func TestCacheAddOverwrites(t *testing.T) {
	c := NewCache()
	if _, err := c.Add(newSHA256, []byte(legacyFIPSName), []byte(wolfGuardID)); err != nil {
		t.Fatalf("Add: %v", err)
	}
	first, _ := c.Get([]byte(legacyFIPSName))

	// Same name, different identifier, as a configuration reload would do.
	if _, err := c.Add(newSHA256, []byte(legacyFIPSName), []byte(wireGuardID)); err != nil {
		t.Fatalf("re-Add: %v", err)
	}
	second, _ := c.Get([]byte(legacyFIPSName))

	if c.Len() != 1 {
		t.Errorf("cache holds %d suites after overwrite, want 1", c.Len())
	}
	if hex.EncodeToString(first.Hash) == hex.EncodeToString(second.Hash) {
		t.Error("re-Add with a different identifier did not replace the stored hash")
	}
}

func TestCacheAddRejectsBadInput(t *testing.T) {
	c := NewCache()
	if _, err := c.Add(nil, []byte(legacyFIPSName), []byte(wolfGuardID)); !errors.Is(err, ErrNoHash) {
		t.Errorf("Add error = %v, want %v", err, ErrNoHash)
	}
	if c.Len() != 0 {
		t.Errorf("a failed Add stored %d suites, want 0", c.Len())
	}
}

// TestCacheConcurrentReads exercises the lock. Run with -race for this to mean
// anything; it is the handshake path's access pattern, many readers against a
// cache built at startup.
func TestCacheConcurrentReads(t *testing.T) {
	c := NewCache()
	if _, err := c.Add(newSHA256, []byte(legacyFIPSName), []byte(wolfGuardID)); err != nil {
		t.Fatalf("Add: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if _, ok := c.Get([]byte(legacyFIPSName)); !ok {
					t.Error("concurrent Get missed a present suite")
					return
				}
			}
		}()
	}
	wg.Wait()
}
