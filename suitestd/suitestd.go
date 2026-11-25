// Package suitestd resolves canonical primitive names to Go's standard library
// and x/crypto.
//
// It is the non-FIPS backend: it proves the mechanism, it needs no cgo, and it
// is what the pure-Go tests use. A FIPS build imports suitewolf instead and
// does not import this package, so the non-approved algorithms it carries,
// X25519, BLAKE2s, ChaCha20-Poly1305 and AES-128, are not in that binary at
// all. An unregistered name is then unreachable rather than merely refused.
//
// Registration is explicit, for the same reason it is in suitewolf: a package
// whose import silently decided which cryptography a program used would be a
// poor thing to have in either build.
package suitestd

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"

	"golang.zx2c4.com/wireguard/suite"
)

// Canonical names this package implements.
const (
	NameX25519               = "X25519"
	NameP256                 = "P-256"
	NameP384                 = "P-384"
	NameHKDFSHA256           = "HKDF-SHA-256"
	NameHKDFSHA384           = "HKDF-SHA-384"
	NameHKDFBLAKE2s256       = "HKDF-BLAKE2S-256"
	NameAEADAES128GCM        = "AEAD_AES_128_GCM"
	NameAEADAES256GCM        = "AEAD_AES_256_GCM"
	NameAEADChaCha20Poly1305 = "AEAD_CHACHA20_POLY1305"
)

// Register installs every implementation this package provides.
//
// Call it once, before any suite is resolved. A build that wants only
// FIPS-approved primitives must not call it.
func Register() {
	suite.RegisterKEX(NameX25519, ecdhKEX{curve: ecdh.X25519(), pubLen: 32, privLen: 32})
	suite.RegisterKEX(NameP256, ecdhKEX{curve: ecdh.P256(), pubLen: 65, privLen: 32})
	suite.RegisterKEX(NameP384, ecdhKEX{curve: ecdh.P384(), pubLen: 97, privLen: 48})

	suite.RegisterKDF(NameHKDFSHA256, sha256.New, hmacOver(sha256.New))
	suite.RegisterKDF(NameHKDFSHA384, sha512.New384, hmacOver(sha512.New384))
	suite.RegisterKDF(NameHKDFBLAKE2s256, newBLAKE2s, hmacOver(newBLAKE2s))

	suite.RegisterAEAD(NameAEADAES128GCM, 16, newAESGCM)
	suite.RegisterAEAD(NameAEADAES256GCM, 32, newAESGCM)
	suite.RegisterAEAD(NameAEADChaCha20Poly1305, 32, chacha20poly1305.New)
}

// hmacOver builds an HMAC constructor from a hash constructor.
//
// This is safe here because both halves come from the same implementation: the
// standard library computes the hash and the HMAC construction around it. A
// backend whose hash lives elsewhere must supply its own HMAC instead.
func hmacOver(newHash func() hash.Hash) func(key []byte) (hash.Hash, error) {
	return func(key []byte) (hash.Hash, error) {
		return hmac.New(newHash, key), nil
	}
}

func newBLAKE2s() hash.Hash {
	// blake2s.New256 only fails for an oversized key, and the key is nil.
	h, err := blake2s.New256(nil)
	if err != nil {
		panic("suitestd: blake2s.New256(nil) cannot fail: " + err.Error())
	}
	return h
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher from a %d byte key: %w", len(key), err)
	}
	/* The handshake's IV is 16 bytes, matching deployed wolfGuard, not RFC
	 * 5116's 12. See the note in suitewolf on why, and on what that means for
	 * the name. */
	return cipher.NewGCMWithNonceSize(block, 16)
}

// ecdhKEX implements suite.KEX over crypto/ecdh.
type ecdhKEX struct {
	curve   ecdh.Curve
	pubLen  int
	privLen int
}

var _ suite.KEX = ecdhKEX{}

func (k ecdhKEX) PublicKeySize() int  { return k.pubLen }
func (k ecdhKEX) PrivateKeySize() int { return k.privLen }

func (k ecdhKEX) GenerateKey() (priv, pub []byte, err error) {
	sk, err := k.curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating key: %w", err)
	}
	return sk.Bytes(), sk.PublicKey().Bytes(), nil
}

func (k ecdhKEX) PublicKey(priv []byte) ([]byte, error) {
	sk, err := k.curve.NewPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("loading a %d byte private key: %w", len(priv), err)
	}
	return sk.PublicKey().Bytes(), nil
}

func (k ecdhKEX) SharedSecret(priv, peerPub []byte) ([]byte, error) {
	sk, err := k.curve.NewPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("loading a %d byte private key: %w", len(priv), err)
	}
	pk, err := k.curve.NewPublicKey(peerPub)
	if err != nil {
		return nil, fmt.Errorf("loading a %d byte peer public key: %w", len(peerPub), err)
	}
	ss, err := sk.ECDH(pk)
	if err != nil {
		return nil, fmt.Errorf("computing shared secret: %w", err)
	}
	return ss, nil
}
