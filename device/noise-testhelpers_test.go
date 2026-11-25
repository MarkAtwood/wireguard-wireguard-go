/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"testing"

	"golang.zx2c4.com/wireguard/suite"
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
