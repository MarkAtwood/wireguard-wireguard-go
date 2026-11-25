// Package suitewolf resolves canonical primitive names to wolfCrypt.
//
// The suite package wires Go's standard library, which proves the mechanism but
// is not a FIPS path: in a FIPS build the crypto has to happen inside the
// validated module. Register installs wolfCrypt implementations under the same
// public names, so a peer naming "P-256" interoperates whichever backend each
// end happens to run.
//
// It is a separate package because it needs cgo and a libwolfssl to link
// against. Keeping it out of suite means suite, wire and their tests stay pure
// Go, so the framing can be built and tested without a wolfSSL toolchain.
//
// Registration is explicit rather than an init side effect: a build that wants
// wolfCrypt says so by calling Register, and a build that does not gets the
// standard library. A package whose import silently changed which cryptography
// a program used would be a poor thing to have in a FIPS product.
//
// What this package does NOT settle: whether a FIPS artifact may also carry the
// non-approved primitives the stock suite needs, X25519, BLAKE2s and
// ChaCha20-Poly1305, as non-approved services. That is a Security Policy
// question, not a code one, and nothing here answers it.
package suitewolf

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"hash"

	wolfSSL "github.com/wolfssl/go-wolfssl"

	"golang.zx2c4.com/wireguard/suite"
)

// Canonical names this package implements. They are the registry names, not
// wolfCrypt's own spellings, because the name is what both peers agreed on.
const (
	NameP256       = "P-256"
	NameHKDFSHA256 = "HKDF-SHA-256"
	NameHKDFSHA384 = "HKDF-SHA-384"
	NameAESGCM256  = "AEAD_AES_256_GCM"
)

// Sizes of the P-256 key material, in the encodings that go on the wire.
const (
	p256PublicKeySize  = 65 // X9.63 uncompressed
	p256PrivateKeySize = 32
	aesGCM256KeySize   = 32
	gcmNonceSize       = 12
	gcmTagSize         = 16
	sha256Size         = 32
	sha256BlockSize    = 64
	sha384Size         = 48
	sha384BlockSize    = 128
)

// Errors reported when wolfCrypt refuses an operation. Each wraps the status
// code, since that is what is diagnosable from a log.
var (
	ErrWolfCrypt = errors.New("suitewolf: wolfCrypt returned an error")
	ErrKeySize   = errors.New("suitewolf: key length does not match the primitive")
)

func wcErr(op string, ret int) error {
	return fmt.Errorf("%s returned %d: %w", op, ret, ErrWolfCrypt)
}

// Register installs the wolfCrypt implementations into the suite package's
// dispatch tables, replacing whatever was registered under those names.
//
// Call it once, before any suite is resolved.
func Register() {
	suite.RegisterKEX(NameP256, P256{})
	suite.RegisterHash(NameHKDFSHA256, NewSHA256)
	suite.RegisterHash(NameHKDFSHA384, NewSHA384)
	suite.RegisterAEAD(NameAESGCM256, aesGCM256KeySize, NewAESGCM)
}

/* ---------- SHA-256 ---------- */

// sha256Hash adapts wolfCrypt's SHA-256 to hash.Hash.
//
// Sum must not disturb the running state, and wolfCrypt's Final both finalises
// and resets, so Sum finalises a copy made with Wc_Sha256Copy. That is why this
// is a real streaming hash rather than a buffer-everything stub.
type sha256Hash struct {
	ctx wolfSSL.Wc_Sha256
	err error
}

var _ hash.Hash = (*sha256Hash)(nil)

// NewSHA256 returns a wolfCrypt-backed SHA-256.
//
// A failure to initialise is recorded and surfaced from Sum, because hash.Hash
// has nowhere to report an error and silently returning a wrong digest would be
// worse than a visible zero one.
func NewSHA256() hash.Hash {
	h := new(sha256Hash)
	if ret := wolfSSL.Wc_InitSha256_ex(&h.ctx, nil, wolfSSL.INVALID_DEVID); ret != 0 {
		h.err = wcErr("Wc_InitSha256_ex", ret)
	}
	return h
}

func (h *sha256Hash) Write(p []byte) (int, error) {
	if h.err != nil {
		return 0, h.err
	}
	if len(p) == 0 {
		return 0, nil
	}
	if ret := wolfSSL.Wc_Sha256Update(&h.ctx, p, len(p)); ret != 0 {
		h.err = wcErr("Wc_Sha256Update", ret)
		return 0, h.err
	}
	return len(p), nil
}

func (h *sha256Hash) Sum(b []byte) []byte {
	out := make([]byte, sha256Size)
	if h.err != nil {
		/* Returning a zero digest is a loud wrong answer rather than a quiet
		 * one: it cannot be mistaken for a real hash of anything. */
		return append(b, out...)
	}

	var snapshot wolfSSL.Wc_Sha256
	if ret := wolfSSL.Wc_InitSha256_ex(&snapshot, nil, wolfSSL.INVALID_DEVID); ret != 0 {
		h.err = wcErr("Wc_InitSha256_ex", ret)
		return append(b, out...)
	}
	defer wolfSSL.Wc_Sha256Free(&snapshot)

	if ret := wolfSSL.Wc_Sha256Copy(&h.ctx, &snapshot); ret != 0 {
		h.err = wcErr("Wc_Sha256Copy", ret)
		return append(b, out...)
	}
	if ret := wolfSSL.Wc_Sha256Final(&snapshot, out); ret != 0 {
		h.err = wcErr("Wc_Sha256Final", ret)
		return append(b, make([]byte, sha256Size)...)
	}
	return append(b, out...)
}

func (h *sha256Hash) Reset() {
	wolfSSL.Wc_Sha256Free(&h.ctx)
	h.err = nil
	if ret := wolfSSL.Wc_InitSha256_ex(&h.ctx, nil, wolfSSL.INVALID_DEVID); ret != 0 {
		h.err = wcErr("Wc_InitSha256_ex", ret)
	}
}

func (h *sha256Hash) Size() int      { return sha256Size }
func (h *sha256Hash) BlockSize() int { return sha256BlockSize }

/* ---------- AES-256-GCM ---------- */

// aesGCM adapts wolfCrypt's AES-GCM to cipher.AEAD.
type aesGCM struct {
	key []byte
}

var _ cipher.AEAD = (*aesGCM)(nil)

// NewAESGCM returns a wolfCrypt-backed AES-256-GCM.
//
// The key is held and the wolfCrypt context built per operation. That is the
// shape the existing handshake code already uses, allocating and freeing an Aes
// around each call, and it keeps this type safe to share across goroutines,
// which cipher.AEAD implementations are expected to be.
func NewAESGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != aesGCM256KeySize {
		return nil, fmt.Errorf("got %d bytes, need %d: %w", len(key), aesGCM256KeySize, ErrKeySize)
	}
	owned := make([]byte, len(key))
	copy(owned, key)
	return &aesGCM{key: owned}, nil
}

func (a *aesGCM) NonceSize() int { return gcmNonceSize }
func (a *aesGCM) Overhead() int  { return gcmTagSize }

// withAes builds a keyed wolfCrypt AES context, runs fn, and frees it.
func (a *aesGCM) withAes(fn func(aes *wolfSSL.Aes) error) error {
	aes := wolfSSL.Wc_AesAllocAligned()
	if aes == nil {
		return fmt.Errorf("Wc_AesAllocAligned returned nil: %w", ErrWolfCrypt)
	}
	defer wolfSSL.Wc_AesFreeAllocAligned(aes)

	if ret := wolfSSL.Wc_AesInit(aes, nil, wolfSSL.INVALID_DEVID); ret != 0 {
		return wcErr("Wc_AesInit", ret)
	}
	defer wolfSSL.Wc_AesFree(aes)

	if ret := wolfSSL.Wc_AesGcmSetKey(aes, a.key, len(a.key)); ret != 0 {
		return wcErr("Wc_AesGcmSetKey", ret)
	}
	return fn(aes)
}

// Seal appends the ciphertext and tag to dst.
//
// It panics on a wolfCrypt failure, which is what cipher.AEAD requires: Seal
// has no error return, and returning a plausible-looking buffer that was never
// encrypted would be far worse than a crash.
func (a *aesGCM) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != gcmNonceSize {
		panic("suitewolf: incorrect nonce length given to AES-GCM")
	}

	out := make([]byte, len(plaintext))
	tag := make([]byte, gcmTagSize)
	err := a.withAes(func(aes *wolfSSL.Aes) error {
		if ret := wolfSSL.Wc_AesGcmEncrypt(aes, out, plaintext, nonce, tag, additionalData); ret != 0 {
			return wcErr("Wc_AesGcmEncrypt", ret)
		}
		return nil
	})
	if err != nil {
		panic("suitewolf: AES-GCM seal failed: " + err.Error())
	}
	return append(append(dst, out...), tag...)
}

// Open authenticates and decrypts, appending the plaintext to dst.
func (a *aesGCM) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != gcmNonceSize {
		return nil, fmt.Errorf("nonce is %d bytes, need %d: %w", len(nonce), gcmNonceSize, ErrKeySize)
	}
	if len(ciphertext) < gcmTagSize {
		return nil, fmt.Errorf("ciphertext is %d bytes, shorter than the %d byte tag: %w",
			len(ciphertext), gcmTagSize, ErrWolfCrypt)
	}

	split := len(ciphertext) - gcmTagSize
	body, tag := ciphertext[:split], ciphertext[split:]
	out := make([]byte, len(body))

	err := a.withAes(func(aes *wolfSSL.Aes) error {
		if ret := wolfSSL.Wc_AesGcmDecrypt(aes, out, body, nonce, tag, additionalData); ret != 0 {
			return wcErr("Wc_AesGcmDecrypt", ret)
		}
		return nil
	})
	if err != nil {
		/* An authentication failure and a mechanical failure are both reported
		 * as a refusal, and neither reveals the plaintext. */
		return nil, err
	}
	return append(dst, out...), nil
}

/* ---------- P-256 ECDH ---------- */

// P256 implements suite.KEX over wolfCrypt's P-256.
//
// Every operation imports and exports raw bytes, which is what the existing
// handshake code already does. X9.63 uncompressed is the same encoding
// crypto/ecdh produces, so a wolfCrypt peer and a stdlib peer agree on the wire.
type P256 struct{}

var _ suite.KEX = P256{}

func (P256) PublicKeySize() int  { return p256PublicKeySize }
func (P256) PrivateKeySize() int { return p256PrivateKeySize }

// GenerateKey draws from wolfCrypt's own RNG, which in a FIPS build is the
// validated module's DRBG. That is why suite.KEX takes no entropy source.
func (k P256) GenerateKey() (priv, pub []byte, err error) {
	var rng wolfSSL.WC_RNG
	var key wolfSSL.Ecc_key

	if ret := wolfSSL.Wc_ecc_init(&key); ret != 0 {
		return nil, nil, wcErr("Wc_ecc_init", ret)
	}
	defer wolfSSL.Wc_ecc_free(&key)

	if ret := wolfSSL.Wc_InitRng(&rng); ret != 0 {
		return nil, nil, wcErr("Wc_InitRng", ret)
	}
	defer wolfSSL.Wc_FreeRng(&rng)

	if ret := wolfSSL.Wc_ecc_make_key(&rng, p256PrivateKeySize, &key); ret != 0 {
		return nil, nil, wcErr("Wc_ecc_make_key", ret)
	}

	privBuf := make([]byte, p256PrivateKeySize)
	privLen := len(privBuf)
	pubBuf := make([]byte, p256PublicKeySize)
	pubLen := len(pubBuf)

	wolfSSL.PRIVATE_KEY_UNLOCK()
	privRet := wolfSSL.Wc_ecc_export_private_only(&key, privBuf, &privLen)
	pubRet := wolfSSL.Wc_ecc_export_x963_ex(&key, pubBuf, &pubLen, 0)
	wolfSSL.PRIVATE_KEY_LOCK()

	if privRet != 0 {
		return nil, nil, wcErr("Wc_ecc_export_private_only", privRet)
	}
	if pubRet != 0 {
		return nil, nil, wcErr("Wc_ecc_export_x963_ex", pubRet)
	}
	return privBuf[:privLen], pubBuf[:pubLen], nil
}

func (k P256) PublicKey(priv []byte) ([]byte, error) {
	if len(priv) != p256PrivateKeySize {
		return nil, fmt.Errorf("private key is %d bytes, need %d: %w",
			len(priv), p256PrivateKeySize, ErrKeySize)
	}

	var key wolfSSL.Ecc_key
	if ret := wolfSSL.Wc_ecc_init(&key); ret != 0 {
		return nil, wcErr("Wc_ecc_init", ret)
	}
	defer wolfSSL.Wc_ecc_free(&key)

	if ret := wolfSSL.Wc_ecc_import_private_key_ex(priv, len(priv), nil, 0, &key, wolfSSL.ECC_SECP256R1); ret != 0 {
		return nil, wcErr("Wc_ecc_import_private_key_ex", ret)
	}
	if ret := wolfSSL.Wc_ecc_make_pub_in_priv(&key); ret != 0 {
		return nil, wcErr("Wc_ecc_make_pub_in_priv", ret)
	}

	pubBuf := make([]byte, p256PublicKeySize)
	pubLen := len(pubBuf)
	wolfSSL.PRIVATE_KEY_UNLOCK()
	ret := wolfSSL.Wc_ecc_export_x963_ex(&key, pubBuf, &pubLen, 0)
	wolfSSL.PRIVATE_KEY_LOCK()
	if ret != 0 {
		return nil, wcErr("Wc_ecc_export_x963_ex", ret)
	}
	return pubBuf[:pubLen], nil
}

func (k P256) SharedSecret(priv, peerPub []byte) ([]byte, error) {
	if len(priv) != p256PrivateKeySize {
		return nil, fmt.Errorf("private key is %d bytes, need %d: %w",
			len(priv), p256PrivateKeySize, ErrKeySize)
	}
	if len(peerPub) != p256PublicKeySize {
		return nil, fmt.Errorf("peer public key is %d bytes, need %d: %w",
			len(peerPub), p256PublicKeySize, ErrKeySize)
	}

	var privKey, pubKey wolfSSL.Ecc_key
	if ret := wolfSSL.Wc_ecc_init(&privKey); ret != 0 {
		return nil, wcErr("Wc_ecc_init", ret)
	}
	defer wolfSSL.Wc_ecc_free(&privKey)
	if ret := wolfSSL.Wc_ecc_init(&pubKey); ret != 0 {
		return nil, wcErr("Wc_ecc_init", ret)
	}
	defer wolfSSL.Wc_ecc_free(&pubKey)

	if ret := wolfSSL.Wc_ecc_import_private_key_ex(priv, len(priv), nil, 0, &privKey, wolfSSL.ECC_SECP256R1); ret != 0 {
		return nil, wcErr("Wc_ecc_import_private_key_ex", ret)
	}
	if ret := wolfSSL.Wc_ecc_import_x963_ex(peerPub, len(peerPub), &pubKey, wolfSSL.ECC_SECP256R1); ret != 0 {
		return nil, wcErr("Wc_ecc_import_x963_ex", ret)
	}

	out := make([]byte, p256PrivateKeySize)
	outLen := len(out)
	wolfSSL.PRIVATE_KEY_UNLOCK()
	ret := wolfSSL.Wc_ecc_shared_secret(&privKey, &pubKey, out, &outLen)
	wolfSSL.PRIVATE_KEY_LOCK()
	if ret != 0 {
		return nil, wcErr("Wc_ecc_shared_secret", ret)
	}
	return out[:outLen], nil
}

/* ---------- SHA-384 ---------- */

// sha384Hash adapts wolfCrypt's SHA-384 to hash.Hash by buffering its input
// and hashing with the one-shot API.
//
// SHA-384 is approved, so a suite naming it is a second FIPS suite, and because
// its digest is 48 bytes where SHA-256's is 32 it also gives a different
// message length. That is what makes a FIPS-to-FIPS migration observable on the
// wire without any non-approved algorithm.
//
// ponytail: buffered rather than streaming, unlike sha256Hash. wolfCrypt's
// SHA-384 context is shaped like a SHA-512 one, and holding it in Go memory
// makes cgo reject the call with "Go pointer to unpinned Go pointer", which
// streaming would require working around with runtime/cgo.Pinner or a
// C-allocated context that go-wolfssl does not expose. Ceiling: memory grows
// with the input, so this is only suitable for the short, one-shot hashing a
// suite does at initialisation, which is the only place a suite's hash is used.
// The handshake's own hashing does not come through here. Upgrade path: pin the
// context, or have go-wolfssl expose an allocator as it does for Aes.
type sha384Hash struct {
	buf []byte
}

var _ hash.Hash = (*sha384Hash)(nil)

// NewSHA384 returns a wolfCrypt-backed SHA-384.
func NewSHA384() hash.Hash {
	return new(sha384Hash)
}

func (h *sha384Hash) Write(p []byte) (int, error) {
	h.buf = append(h.buf, p...)
	return len(p), nil
}

func (h *sha384Hash) Sum(b []byte) []byte {
	out := make([]byte, sha384Size)
	if ret := wolfSSL.Wc_Sha384Hash(h.buf, len(h.buf), out); ret != 0 {
		/* A zero digest is a loud wrong answer rather than a quiet one. */
		return append(b, make([]byte, sha384Size)...)
	}
	return append(b, out...)
}

func (h *sha384Hash) Reset()         { h.buf = nil }
func (h *sha384Hash) Size() int      { return sha384Size }
func (h *sha384Hash) BlockSize() int { return sha384BlockSize }
