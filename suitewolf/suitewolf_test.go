package suitewolf

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"hash"
	"strings"
	"testing"

	wolfSSL "github.com/wolfssl/go-wolfssl"

	"golang.zx2c4.com/wireguard/suite"
	"golang.zx2c4.com/wireguard/suitestd"
)

// Vectors produced by python-cryptography 41.0.7, an OpenSSL-backed
// implementation independent of both wolfCrypt and Go, via scratchpad/genvec.py.
const (
	p256PrivA  = "1111111111111111111111111111111111111111111111111111111111111111"
	p256PubA   = "040217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c65306e5794"
	p256PrivB  = "2222222222222222222222222222222222222222222222222222222222222222"
	p256PubB   = "04d65a93977caa3d1b081852ff57a79e465f1660577304baead505dd3a48589cf350185e895372df6221ea3a137557e473fddb6755f05bd507c3c533fce9c91285"
	p256Shared = "ccfc261f58193c98ca4ad4a53bbac6f0ee29bc4d48438090446908622ca79af6"

	aeadKey   = "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc"
	aeadNonce = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
	aeadPT    = "776f6c664775617264206e616d65642d616c676f2070726f746f74797065"
	aeadAAD   = "6173736f6369617465642d64617461"
	aesGCMCT  = "7dba89b08ca99951f3a4e72133d6d698b6d8b5bf093f58ac799e347224956c0fc9cafc243fe6b8e7ad8d4b4e2919"
)

func init() { Register() }

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decoding vector: %v", err)
	}
	return b
}

/* ---------- SHA-256 ---------- */

// TestSHA256AgreesWithStdlib cross-validates against crypto/sha256 across
// input shapes, including the chunked writes a streaming hash has to handle.
func TestSHA256AgreesWithStdlib(t *testing.T) {
	tests := []struct {
		name   string
		chunks []string
	}{
		{name: "empty", chunks: nil},
		{name: "single byte", chunks: []string{"a"}},
		{name: "one write", chunks: []string{"Noise_IKpsk2_SECP256R1_AesGcm_SHA256"}},
		{name: "two writes", chunks: []string{"Noise_IKpsk2_", "SECP256R1_AesGcm_SHA256"}},
		{name: "many small writes", chunks: strings.Split("abcdefghijklmnopqrstuvwxyz", "")},
		{name: "spanning a block", chunks: []string{strings.Repeat("x", 64), strings.Repeat("y", 7)}},
		{name: "several blocks", chunks: []string{strings.Repeat("z", 200)}},
		{name: "empty write among others", chunks: []string{"abc", "", "def"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wolf := NewSHA256()
			std := sha256.New()
			for _, c := range tt.chunks {
				if _, err := wolf.Write([]byte(c)); err != nil {
					t.Fatalf("wolfCrypt Write: %v", err)
				}
				std.Write([]byte(c))
			}
			if got, want := wolf.Sum(nil), std.Sum(nil); !bytes.Equal(got, want) {
				t.Errorf("digest = %x, stdlib = %x", got, want)
			}
			if got, want := wolf.Size(), std.Size(); got != want {
				t.Errorf("Size = %d, stdlib = %d", got, want)
			}
			if got, want := wolf.BlockSize(), std.BlockSize(); got != want {
				t.Errorf("BlockSize = %d, stdlib = %d", got, want)
			}
		})
	}
}

// TestSHA256SumDoesNotDisturbState is the property the Wc_Sha256Copy dance
// exists for: hash.Hash requires Sum to leave the running state untouched, and
// wolfCrypt's Final both finalises and resets.
func TestSHA256SumDoesNotDisturbState(t *testing.T) {
	wolf := NewSHA256()
	std := sha256.New()

	write := func(s string) {
		t.Helper()
		if _, err := wolf.Write([]byte(s)); err != nil {
			t.Fatalf("Write: %v", err)
		}
		std.Write([]byte(s))
	}

	write("first")
	first, stdFirst := wolf.Sum(nil), std.Sum(nil)
	if !bytes.Equal(first, stdFirst) {
		t.Fatalf("first digest = %x, stdlib = %x", first, stdFirst)
	}

	// Writing after Sum must continue the same hash, not start a new one.
	write("second")
	second, stdSecond := wolf.Sum(nil), std.Sum(nil)
	if !bytes.Equal(second, stdSecond) {
		t.Errorf("after a further write, digest = %x, stdlib = %x", second, stdSecond)
	}
	if bytes.Equal(first, second) {
		t.Error("Sum returned the same digest after more data was written")
	}

	// Sum twice in a row must agree.
	if a, b := wolf.Sum(nil), wolf.Sum(nil); !bytes.Equal(a, b) {
		t.Errorf("consecutive Sums disagree: %x then %x", a, b)
	}
}

func TestSHA256Reset(t *testing.T) {
	wolf := NewSHA256()
	if _, err := wolf.Write([]byte("discarded")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	wolf.Reset()
	if _, err := wolf.Write([]byte("kept")); err != nil {
		t.Fatalf("Write after Reset: %v", err)
	}

	std := sha256.Sum256([]byte("kept"))
	if got := wolf.Sum(nil); !bytes.Equal(got, std[:]) {
		t.Errorf("after Reset digest = %x, want %x", got, std[:])
	}
}

// TestSHA256SumAppends checks the hash.Hash contract that Sum extends its
// argument rather than replacing it.
func TestSHA256SumAppends(t *testing.T) {
	prefix := []byte{0xde, 0xad}
	got := NewSHA256().Sum(prefix)
	if !bytes.Equal(got[:2], prefix) {
		t.Errorf("Sum overwrote its argument: %x", got)
	}
	if len(got) != len(prefix)+sha256Size {
		t.Errorf("Sum returned %d bytes, want %d", len(got), len(prefix)+sha256Size)
	}
}

/* ---------- AES-256-GCM ---------- */

func stdGCM(t *testing.T, key []byte) cipher.AEAD {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	a, err := cipher.NewGCMWithNonceSize(block, gcmNonceSize)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	return a
}

// TestAESGCMAgreesWithVectorAndStdlib checks wolfCrypt against the
// python-cryptography vector and against Go's own GCM.
func TestAESGCMAgreesWithVectorAndStdlib(t *testing.T) {
	key, nonce := unhex(t, aeadKey), unhex(t, aeadNonce)
	pt, aad := unhex(t, aeadPT), unhex(t, aeadAAD)

	wolf, err := NewAESGCM(key)
	if err != nil {
		t.Fatalf("NewAESGCM: %v", err)
	}
	got := wolf.Seal(nil, nonce, pt, aad)

	if want := unhex(t, aesGCMCT); !bytes.Equal(got, want) {
		t.Errorf("Seal = %x\n want %x (python-cryptography)", got, want)
	}
	if want := stdGCM(t, key).Seal(nil, nonce, pt, aad); !bytes.Equal(got, want) {
		t.Errorf("Seal = %x\n want %x (crypto/cipher)", got, want)
	}
	if got, want := wolf.NonceSize(), 16; got != want {
		t.Errorf("NonceSize = %d, want %d", got, want)
	}
	if got, want := wolf.Overhead(), gcmTagSize; got != want {
		t.Errorf("Overhead = %d, want %d", got, want)
	}
}

// TestAESGCMInteroperatesWithStdlib is the interop check in both directions,
// which is what matters if one peer runs wolfCrypt and another the stdlib.
func TestAESGCMInteroperatesWithStdlib(t *testing.T) {
	key, nonce := unhex(t, aeadKey), unhex(t, aeadNonce)
	pt, aad := unhex(t, aeadPT), unhex(t, aeadAAD)

	wolf, err := NewAESGCM(key)
	if err != nil {
		t.Fatalf("NewAESGCM: %v", err)
	}
	std := stdGCM(t, key)

	t.Run("stdlib seals, wolfCrypt opens", func(t *testing.T) {
		out, err := wolf.Open(nil, nonce, std.Seal(nil, nonce, pt, aad), aad)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if !bytes.Equal(out, pt) {
			t.Errorf("plaintext = %x, want %x", out, pt)
		}
	})

	t.Run("wolfCrypt seals, stdlib opens", func(t *testing.T) {
		out, err := std.Open(nil, nonce, wolf.Seal(nil, nonce, pt, aad), aad)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if !bytes.Equal(out, pt) {
			t.Errorf("plaintext = %x, want %x", out, pt)
		}
	})
}

func TestAESGCMRejectsTampering(t *testing.T) {
	key, nonce := unhex(t, aeadKey), unhex(t, aeadNonce)
	pt, aad := unhex(t, aeadPT), unhex(t, aeadAAD)

	wolf, err := NewAESGCM(key)
	if err != nil {
		t.Fatalf("NewAESGCM: %v", err)
	}
	sealed := wolf.Seal(nil, nonce, pt, aad)

	tests := []struct {
		name   string
		mangle func(ct []byte) ([]byte, []byte)
	}{
		{
			name:   "flipped ciphertext byte",
			mangle: func(ct []byte) ([]byte, []byte) { ct[0] ^= 0x01; return ct, aad },
		},
		{
			name:   "flipped tag byte",
			mangle: func(ct []byte) ([]byte, []byte) { ct[len(ct)-1] ^= 0x01; return ct, aad },
		},
		{
			name:   "altered associated data",
			mangle: func(ct []byte) ([]byte, []byte) { return ct, []byte("different-aad") },
		},
		{
			name:   "truncated below the tag",
			mangle: func(ct []byte) ([]byte, []byte) { return ct[:gcmTagSize-1], aad },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ct := append([]byte{}, sealed...)
			ct, useAAD := tt.mangle(ct)
			if out, err := wolf.Open(nil, nonce, ct, useAAD); err == nil {
				t.Errorf("Open accepted a tampered message, returning %x", out)
			}
		})
	}
}

func TestAESGCMRejectsBadKeyAndNonce(t *testing.T) {
	if _, err := NewAESGCM(make([]byte, 16)); !errors.Is(err, ErrKeySize) {
		t.Errorf("NewAESGCM accepted a 16 byte key: %v", err)
	}
	wolf, err := NewAESGCM(unhex(t, aeadKey))
	if err != nil {
		t.Fatalf("NewAESGCM: %v", err)
	}
	if _, err := wolf.Open(nil, make([]byte, 12), make([]byte, 32), nil); !errors.Is(err, ErrKeySize) {
		t.Errorf("Open accepted a 12 byte nonce, but the protocol uses 16: %v", err)
	}
}

/* ---------- P-256 ---------- */

// TestP256AgreesWithVectors checks wolfCrypt's ECDH against
// python-cryptography's shared secret and derived public keys.
func TestP256AgreesWithVectors(t *testing.T) {
	var k P256

	t.Run("public key derivation", func(t *testing.T) {
		for _, c := range []struct{ priv, wantPub string }{
			{p256PrivA, p256PubA},
			{p256PrivB, p256PubB},
		} {
			got, err := k.PublicKey(unhex(t, c.priv))
			if err != nil {
				t.Fatalf("PublicKey: %v", err)
			}
			if hex.EncodeToString(got) != c.wantPub {
				t.Errorf("PublicKey = %x, want %s", got, c.wantPub)
			}
		}
	})

	t.Run("shared secret", func(t *testing.T) {
		got, err := k.SharedSecret(unhex(t, p256PrivA), unhex(t, p256PubB))
		if err != nil {
			t.Fatalf("SharedSecret: %v", err)
		}
		if hex.EncodeToString(got) != p256Shared {
			t.Errorf("SharedSecret = %x, want %s", got, p256Shared)
		}

		// And the other direction must agree, as ECDH requires.
		other, err := k.SharedSecret(unhex(t, p256PrivB), unhex(t, p256PubA))
		if err != nil {
			t.Fatalf("SharedSecret (reversed): %v", err)
		}
		if !bytes.Equal(got, other) {
			t.Errorf("the two directions disagree: %x and %x", got, other)
		}
	})
}

// TestP256InteroperatesWithStdlib is the interop check that matters for a mixed
// fleet: a key generated by wolfCrypt must work against crypto/ecdh and vice
// versa, with both sides computing the same secret.
func TestP256InteroperatesWithStdlib(t *testing.T) {
	var k P256
	curve := ecdh.P256()

	wolfPriv, wolfPub, err := k.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if len(wolfPub) != k.PublicKeySize() {
		t.Errorf("generated public key is %d bytes, PublicKeySize says %d", len(wolfPub), k.PublicKeySize())
	}
	if len(wolfPriv) != k.PrivateKeySize() {
		t.Errorf("generated private key is %d bytes, PrivateKeySize says %d", len(wolfPriv), k.PrivateKeySize())
	}

	stdPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("stdlib GenerateKey: %v", err)
	}
	stdPub := stdPriv.PublicKey().Bytes()

	// wolfCrypt's view.
	wolfSS, err := k.SharedSecret(wolfPriv, stdPub)
	if err != nil {
		t.Fatalf("wolfCrypt SharedSecret: %v", err)
	}

	// The stdlib's view of the same pair.
	wolfPubParsed, err := curve.NewPublicKey(wolfPub)
	if err != nil {
		t.Fatalf("stdlib rejected a wolfCrypt public key: %v", err)
	}
	stdSS, err := stdPriv.ECDH(wolfPubParsed)
	if err != nil {
		t.Fatalf("stdlib ECDH: %v", err)
	}

	if !bytes.Equal(wolfSS, stdSS) {
		t.Errorf("wolfCrypt computed %x, stdlib computed %x", wolfSS, stdSS)
	}

	// The stdlib must also accept wolfCrypt's derived public key as matching
	// its private key, which catches an encoding mismatch.
	derived, err := k.PublicKey(wolfPriv)
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if !bytes.Equal(derived, wolfPub) {
		t.Errorf("PublicKey gave %x but GenerateKey gave %x", derived, wolfPub)
	}
}

func TestP256RejectsBadLengths(t *testing.T) {
	var k P256
	if _, err := k.PublicKey(make([]byte, 31)); !errors.Is(err, ErrKeySize) {
		t.Errorf("PublicKey accepted a 31 byte private key: %v", err)
	}
	if _, err := k.SharedSecret(make([]byte, 32), make([]byte, 64)); !errors.Is(err, ErrKeySize) {
		t.Errorf("SharedSecret accepted a 64 byte peer key: %v", err)
	}
}

/* ---------- registration ---------- */

// TestBothBackendsDeriveTheSameState is the deployment-critical property.
//
// The same handshake name must produce the same chaining key whichever backend
// computes it, because SHA-256 is SHA-256. If registering wolfCrypt moved the
// chaining key, every peer in the field would become unreachable. Both are
// checked against a value computed with coreutils, so neither backend is its
// own oracle.
func TestBothBackendsDeriveTheSameState(t *testing.T) {
	const (
		legacyName = "Noise_IKpsk2_SECP256R1_AesGcm_SHA256"
		identifier = "WolfGuard v1 info@wolfssl.com"
		// printf '%s' "$NAME" | sha256sum, then the hash of that digest
		// concatenated with the identifier.
		wantChainKey = "082dafe0b19fee706a69f2b95ca6e1369fabd5365f0e91622574735b7f24be48"
		wantHash     = "05b688c3b96ec779407780baecbf198e39a13d2c427445ef2839cb5e211b6a00"
	)

	derive := func(t *testing.T, register func()) *suite.Suite {
		t.Helper()
		register()
		r := suite.NewRegistry()
		s, err := r.AcceptLegacy([]byte(legacyName), NameP256, NameHKDFSHA256, NameAESGCM256, []byte(identifier))
		if err != nil {
			t.Fatalf("AcceptLegacy: %v", err)
		}
		return s
	}

	std := derive(t, suitestd.Register)
	wolf := derive(t, Register)

	// The key exchange really is the wolfCrypt one after Register.
	if _, ok := wolf.KEX.(P256); !ok {
		t.Errorf("after Register the KEX is %T, want suitewolf.P256", wolf.KEX)
	}

	for _, c := range []struct {
		backend string
		s       *suite.Suite
	}{{"suitestd", std}, {"suitewolf", wolf}} {
		if got := hex.EncodeToString(c.s.State.ChainKey); got != wantChainKey {
			t.Errorf("%s chain key = %s, want %s", c.backend, got, wantChainKey)
		}
		if got := hex.EncodeToString(c.s.State.Hash); got != wantHash {
			t.Errorf("%s hash = %s, want %s", c.backend, got, wantHash)
		}
	}
	if !bytes.Equal(std.State.ChainKey, wolf.State.ChainKey) {
		t.Errorf("the backends disagree on the chain key: %x and %x",
			std.State.ChainKey, wolf.State.ChainKey)
	}
	if std.KEX.PublicKeySize() != wolf.KEX.PublicKeySize() {
		t.Errorf("the backends disagree on public key size: %d and %d",
			std.KEX.PublicKeySize(), wolf.KEX.PublicKeySize())
	}
}

// TestSHA384AgreesWithStdlib cross-validates the second approved hash, which is
// what makes a FIPS-to-FIPS migration observable: its 48 byte digest gives a
// different message length from SHA-256's 32.
func TestSHA384AgreesWithStdlib(t *testing.T) {
	for _, chunks := range [][]string{
		nil,
		{"a"},
		{"Noise_IKpsk2_SECP256R1_AesGcm_SHA256"},
		{"Noise_", "IKpsk2_", "SECP256R1"},
		{strings.Repeat("x", 128), strings.Repeat("y", 13)},
	} {
		wolf := NewSHA384()
		std := sha512.New384()
		for _, c := range chunks {
			if _, err := wolf.Write([]byte(c)); err != nil {
				t.Fatalf("Write: %v", err)
			}
			std.Write([]byte(c))
		}
		if got, want := wolf.Sum(nil), std.Sum(nil); !bytes.Equal(got, want) {
			t.Errorf("digest = %x, stdlib = %x", got, want)
		}
		if got, want := wolf.Size(), std.Size(); got != want {
			t.Errorf("Size = %d, stdlib = %d", got, want)
		}
	}
}

// TestSHA384SumDoesNotDisturbState mirrors the SHA-256 check, since the same
// Copy-before-Final requirement applies.
func TestSHA384SumDoesNotDisturbState(t *testing.T) {
	wolf := NewSHA384()
	std := sha512.New384()
	for _, c := range []string{"first", "second"} {
		if _, err := wolf.Write([]byte(c)); err != nil {
			t.Fatalf("Write: %v", err)
		}
		std.Write([]byte(c))
		if got, want := wolf.Sum(nil), std.Sum(nil); !bytes.Equal(got, want) {
			t.Fatalf("after %q digest = %x, stdlib = %x", c, got, want)
		}
	}
}

// TestHMACAgreesWithStdlib cross-validates the wolfCrypt HMAC against
// crypto/hmac over the same hash, for both approved hashes.
//
// This matters more than the hash check: the handshake's key derivation is
// HKDF, so every handshake key comes out of this MAC. A disagreement here means
// two peers derive different keys.
func TestHMACAgreesWithStdlib(t *testing.T) {
	tests := []struct {
		name     string
		hashType int
		size     int
		newHash  func() hash.Hash
	}{
		{name: "HMAC-SHA-256", hashType: wolfSSL.WC_SHA256, size: 32, newHash: sha256.New},
		{name: "HMAC-SHA-384", hashType: wolfSSL.WC_SHA384, size: 48, newHash: sha512.New384},
	}

	keys := [][]byte{
		[]byte("k"),
		bytes.Repeat([]byte{0xAA}, 32),
		bytes.Repeat([]byte{0x5A}, 64),
		bytes.Repeat([]byte{0x11}, 200), // longer than the block size
	}
	inputs := [][]string{
		nil,
		{"a"},
		{"Noise_IKpsk2_SECP256R1_AesGcm_SHA256"},
		{"chunk one ", "chunk two ", "chunk three"},
		{strings.Repeat("x", 300)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctor := newHMAC(tt.hashType, tt.size)
			for ki, key := range keys {
				for ii, chunks := range inputs {
					wolf, err := ctor(key)
					if err != nil {
						t.Fatalf("constructing HMAC: %v", err)
					}
					std := hmac.New(tt.newHash, key)
					for _, c := range chunks {
						if _, err := wolf.Write([]byte(c)); err != nil {
							t.Fatalf("Write: %v", err)
						}
						std.Write([]byte(c))
					}
					got, want := wolf.Sum(nil), std.Sum(nil)
					if !bytes.Equal(got, want) {
						t.Errorf("key %d input %d: HMAC = %x, stdlib = %x", ki, ii, got, want)
					}
					if len(got) != tt.size {
						t.Errorf("HMAC is %d bytes, want %d", len(got), tt.size)
					}
					if wolf.Size() != std.Size() {
						t.Errorf("Size = %d, stdlib = %d", wolf.Size(), std.Size())
					}
					if wolf.BlockSize() != std.BlockSize() {
						t.Errorf("BlockSize = %d, stdlib = %d", wolf.BlockSize(), std.BlockSize())
					}
				}
			}
		})
	}
}

// TestHMACResetRekeys checks that Reset makes the value reusable for another
// MAC under the same key, which is what the KDF needs when it reuses one.
func TestHMACResetRekeys(t *testing.T) {
	ctor := newHMAC(wolfSSL.WC_SHA256, 32)
	key := bytes.Repeat([]byte{0x42}, 32)

	wolf, err := ctor(key)
	if err != nil {
		t.Fatalf("constructing HMAC: %v", err)
	}
	if _, err := wolf.Write([]byte("first")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	first := wolf.Sum(nil)

	wolf.Reset()
	if _, err := wolf.Write([]byte("second")); err != nil {
		t.Fatalf("Write after Reset: %v", err)
	}
	second := wolf.Sum(nil)

	std := hmac.New(sha256.New, key)
	std.Write([]byte("second"))
	if want := std.Sum(nil); !bytes.Equal(second, want) {
		t.Errorf("after Reset HMAC = %x, want %x", second, want)
	}
	if bytes.Equal(first, second) {
		t.Error("Reset did not change the running state")
	}
}

func TestHMACRejectsEmptyKey(t *testing.T) {
	if _, err := newHMAC(wolfSSL.WC_SHA256, 32)(nil); !errors.Is(err, ErrKeySize) {
		t.Errorf("empty key error = %v, want %v", err, ErrKeySize)
	}
}
