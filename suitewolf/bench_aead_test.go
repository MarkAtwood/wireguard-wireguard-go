package suitewolf

import (
	"testing"

	wolfSSL "github.com/wolfssl/go-wolfssl"
)

// payload is a full-MTU transport packet, padded to the multiple of 16 the
// transport path pads to.
const payload = 1424

// BenchmarkSealInPlaceRaw is the transport path as it stands: a wolfCrypt
// context allocated, keyed and freed per packet, encrypting in place.
func BenchmarkSealInPlaceRaw(b *testing.B) {
	key := make([]byte, 32)
	nonce := make([]byte, 16)
	buf := make([]byte, payload, payload+16)

	b.SetBytes(payload)
	for i := 0; i < b.N; i++ {
		aes := wolfSSL.Wc_AesAllocAligned()
		wolfSSL.Wc_AesInit(aes, nil, wolfSSL.INVALID_DEVID)
		wolfSSL.Wc_AesGcmSetKey(aes, key, len(key))
		wolfSSL.Wc_AesGcm_Appended_Tag_Encrypt(aes, buf, buf[:payload], nonce, nil)
		wolfSSL.Wc_AesFree(aes)
		wolfSSL.Wc_AesFreeAllocAligned(aes)
	}
}

// BenchmarkSealThroughAEAD is the same work through the suite's cipher.AEAD,
// which is what making the data path suite-driven would use.
func BenchmarkSealThroughAEAD(b *testing.B) {
	Register()
	aead, err := NewAESGCM(make([]byte, 32))
	if err != nil {
		b.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	plaintext := make([]byte, payload)
	dst := make([]byte, 0, payload+aead.Overhead())

	b.SetBytes(payload)
	for i := 0; i < b.N; i++ {
		_ = aead.Seal(dst[:0], nonce, plaintext, nil)
	}
}
