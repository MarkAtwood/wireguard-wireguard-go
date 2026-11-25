/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.zx2c4.com/wireguard/suite"
	"golang.zx2c4.com/wireguard/suitestd"
	"golang.zx2c4.com/wireguard/suitewolf"
)

// testKEX is the key exchange the tests use when there is no device to ask.
//
// It is wolfCrypt's P-256, the same implementation a real device resolves
// "P-256" to, so a test is not quietly exercising a different backend from
// production.
func testKEX() suite.KEX {
	registerBackend.Do(suitewolf.Register)
	return suitewolf.P256{}
}

// publicKeyOrFatal derives a public key, failing the test rather than returning
// an error, which keeps the call sites readable.
func (sk *NoisePrivateKey) publicKeyOrFatal(tb testing.TB) NoisePublicKey {
	tb.Helper()
	pk, err := sk.publicKey(testKEX())
	if err != nil {
		tb.Fatalf("deriving a public key: %v", err)
	}
	return pk
}

// testHMAC is the HMAC the tests use when there is no device to ask. It is
// wolfCrypt's HMAC-SHA-256, the same one a real device resolves
// "HKDF-SHA-256" to.
func testHMAC() hmacFunc {
	registerBackend.Do(suitewolf.Register)
	s, err := suite.Resolve(suitewolf.NameP256, suitewolf.NameHKDFSHA256, suitewolf.NameAESGCM256)
	if err != nil {
		panic("suitewolf did not register its own names: " + err.Error())
	}
	return s.NewHMAC
}

// testLegacySuite is the deployed suite, resolved the way a real device
// resolves it: through a registry, so it carries its handshake name and its
// precomputed initial state. Tests that need a suite to hand to the handshake
// or the cookie mechanism use this rather than suite.Resolve, which produces
// the primitives but no name, and the name is what identifies a suite.
func testLegacySuite(tb testing.TB) *suite.Suite {
	tb.Helper()
	var device Device
	device.log = NewLogger(LogLevelSilent, "")
	if err := device.initSuites(); err != nil {
		tb.Fatalf("initSuites: %v", err)
	}
	s, _ := device.localSuite()
	if s == nil {
		tb.Fatal("initSuites left the device without a local suite")
	}
	return s
}

// registerChaCha20ForTest makes AEAD_CHACHA20_POLY1305 resolvable, which is how
// a test reaches an AEAD the wolfCrypt backend does not offer. Its nonce is 12
// bytes where AES-GCM's is 16, and that difference is what makes the data
// path's nonce handling observable at all.
//
// It deliberately registers one AEAD rather than calling suitestd.Register().
// That function also registers P-256, HKDF-SHA-256 and AEAD_AES_256_GCM, and
// registration replaces an existing entry, so calling it would silently move
// every other test in this binary off wolfCrypt and onto the Go standard
// library while still claiming to exercise the FIPS backend.
//
// It does mutate the suite package's process-wide tables for the rest of this
// binary. That is tolerable here and nowhere else: the assertion that a FIPS
// build cannot resolve a non-approved name lives in the suite package's own
// tests, which build as a separate binary, so nothing here can weaken it. A
// shipped wolfGuard links suitewolf alone, which is what makes these
// algorithms absent rather than merely refused.
func registerChaCha20ForTest(tb testing.TB) {
	tb.Helper()
	suite.RegisterAEAD(suitestd.NameAEADChaCha20Poly1305, chacha20poly1305.KeySize, chacha20poly1305.New)
}

// transportRoundTrip pushes one packet through a session in one direction,
// built the way the data path builds it: a nonce of the AEAD's own length
// carrying the counter at TransportNonceCounterOffset and nothing else set.
//
// It is the data-plane counterpart of the handshake's transcript assertions,
// and it replaced comparing the two ends' key bytes. A Keypair holds a cipher
// rather than a key now, so what can be checked is the thing that actually
// matters: that traffic survives the round trip under the nonce layout the
// workers use.
func transportRoundTrip(tb testing.TB, from, to *Keypair, counter uint64, plaintext []byte) {
	tb.Helper()

	sealNonce := make([]byte, from.send.NonceSize())
	binary.LittleEndian.PutUint64(sealNonce[TransportNonceCounterOffset:], counter)
	sealed := from.send.Seal(nil, sealNonce, plaintext, nil)

	if want := len(plaintext) + from.send.Overhead(); len(sealed) != want {
		tb.Fatalf("sealed %d bytes, want %d plaintext plus a %d byte tag",
			len(sealed), len(plaintext), from.send.Overhead())
	}

	openNonce := make([]byte, to.receive.NonceSize())
	binary.LittleEndian.PutUint64(openNonce[TransportNonceCounterOffset:], counter)
	opened, err := to.receive.Open(nil, openNonce, sealed, nil)
	if err != nil {
		tb.Fatalf("the receiving end could not open the packet: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		tb.Fatalf("round trip gave %x, want %x", opened, plaintext)
	}

	// The counter is bound into the nonce, so the same bytes under a different
	// counter must not authenticate. Without that the nonce could be ignored
	// entirely and this round trip would still pass.
	wrong := make([]byte, to.receive.NonceSize())
	binary.LittleEndian.PutUint64(wrong[TransportNonceCounterOffset:], counter+1)
	if _, err := to.receive.Open(nil, wrong, sealed, nil); err == nil {
		tb.Error("a packet authenticated under the wrong counter")
	}
}
