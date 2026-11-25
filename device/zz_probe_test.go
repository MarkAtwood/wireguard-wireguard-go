/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

// This file is the two-live-suite migration demo. It wants renaming to
// migration_demo_test.go; it kept a scratch name because the sandbox would not
// permit the rename.

package device

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"golang.zx2c4.com/wireguard/wire"
)

// sha384SuiteName is a second suite with different algorithms, and therefore
// different message lengths, from the deployed one.
const sha384SuiteName = ":P-256:HKDF-SHA-384:AEAD_AES_256_GCM"

// TestMigrationResponderServesTwoLiveSuites is the migration demo at the
// framing level: one device accepting two suites at once, routing an inbound
// handshake to the right layout by its length, with each suite keeping its own
// chaining key.
//
// This is the state a fleet is in mid-migration, when some peers have moved to
// the new suite and some have not.
func TestMigrationResponderServesTwoLiveSuites(t *testing.T) {
	var device Device
	device.log = NewLogger(LogLevelSilent, "")
	if err := device.initSuites(); err != nil {
		t.Fatalf("initSuites: %v", err)
	}

	legacy, legacyLayout := device.localSuite()
	sha384, err := device.AcceptSuite([]byte(sha384SuiteName), []byte(LegacyIdentifier))
	if err != nil {
		t.Fatalf("accepting the second suite: %v", err)
	}
	sha384Layout, err := wire.LayoutFor(sha384)
	if err != nil {
		t.Fatalf("LayoutFor: %v", err)
	}

	t.Logf("legacy %q: initiation %d bytes", legacy.Name(), legacyLayout.InitiationSize())
	t.Logf("sha384 %q: initiation %d bytes", sha384.Name(), sha384Layout.InitiationSize())

	// 1. The two suites are genuinely distinct, in keys and in framing.
	if bytes.Equal(legacy.State.ChainKey, sha384.State.ChainKey) {
		t.Error("the two live suites share a chaining key")
	}
	if legacyLayout.InitiationSize() == sha384Layout.InitiationSize() {
		t.Fatal("the two suites do not differ in length, so this demo proves nothing")
	}

	// 2. Both are accepted, and each length routes to its own layout. This is
	//    what the receive path does before it knows which peer is sending.
	for _, c := range []struct {
		name   string
		size   int
		expect wire.Layout
	}{
		{"legacy", legacyLayout.InitiationSize(), legacyLayout},
		{"sha384", sha384Layout.InitiationSize(), sha384Layout},
	} {
		t.Run("routes "+c.name, func(t *testing.T) {
			if !device.acceptsInitiationSize(c.size) {
				t.Fatalf("device rejects a %d byte initiation", c.size)
			}
			got, ok := device.layoutForInitiationSize(c.size)
			if !ok {
				t.Fatalf("no layout for a %d byte initiation", c.size)
			}
			if got != c.expect {
				t.Errorf("routed to %+v, want %+v", got, c.expect)
			}
		})
	}

	// 3. A message framed under one suite must not decode under the other,
	//    which is what keeps the two populations from being confused.
	legacyPacket := make([]byte, legacyLayout.InitiationSize())
	if _, err := sha384Layout.ParseInitiation(legacyPacket); !errors.Is(err, wire.ErrSize) {
		t.Errorf("a legacy-sized packet parsed under the SHA-384 layout: %v", err)
	}

	// 4. Peers are moved one at a time. An unpinned peer stays on the device
	//    suite, which is how a migration is sequenced rather than flag-dayed.
	moved := &Peer{device: &device}
	if err := moved.SetSuite(sha384); err != nil {
		t.Fatalf("SetSuite: %v", err)
	}
	notMoved := &Peer{device: &device}

	if s, _ := moved.suiteFor(); s != sha384 {
		t.Error("the moved peer is not on the SHA-384 suite")
	}
	if s, _ := notMoved.suiteFor(); s != legacy {
		t.Error("the unmoved peer did not stay on the device suite")
	}

	// 5. The receive buffer has to fit the larger of the two.
	if got, want := device.maxHandshakeSize(), sha384Layout.InitiationSize(); got != want {
		t.Errorf("maxHandshakeSize = %d, want %d (the larger of the two)", got, want)
	}
}

// TestHashIsNotDispatchedYet pins the remaining gap, so it is a
// failing-when-fixed assertion rather than a note someone has to remember.
//
// The two live suites now differ only in their hash: SHA-256 against SHA-384,
// both approved. The suite's layout follows, giving 48 byte MACs instead of 32
// and a 278 byte initiation instead of 246. But the handshake still computes
// mac1, mac2 and every mixHash with wolfCrypt SHA-256 directly, so a peer
// pinned to the SHA-384 suite produces 32 byte MACs for a layout that wants 48.
//
// Encoding therefore refuses, which is the good news: wire's field-length check
// will not emit a packet whose MACs are the wrong size for the suite its own
// name declares.
//
// When the hash is dispatched through the suite, this test fails and whoever
// sees it should replace it with a real two-suite handshake.
func TestHashIsNotDispatchedYet(t *testing.T) {
	var device Device
	device.log = NewLogger(LogLevelSilent, "")
	if err := device.initSuites(); err != nil {
		t.Fatalf("initSuites: %v", err)
	}
	sha384, err := device.AcceptSuite([]byte(sha384SuiteName), []byte(LegacyIdentifier))
	if err != nil {
		t.Fatalf("AcceptSuite: %v", err)
	}

	peer := &Peer{device: &device}
	if err := peer.SetSuite(sha384); err != nil {
		t.Fatalf("SetSuite: %v", err)
	}
	_, layout := peer.suiteFor()

	// The suite says 48 byte MACs.
	if got := sha384.NewHash().Size(); got != 48 {
		t.Fatalf("the SHA-384 suite's hash is %d bytes, want 48", got)
	}
	if layout.MACSize != 48 {
		t.Fatalf("the SHA-384 layout wants %d byte MACs, want 48", layout.MACSize)
	}

	// The key exchange IS dispatched: both suites name P-256, and the peer's
	// key exchange produces the size its layout expects.
	sk, err := newPrivateKey(peer.kex())
	if err != nil {
		t.Fatalf("newPrivateKey: %v", err)
	}
	pk, err := sk.publicKey(peer.kex())
	if err != nil {
		t.Fatalf("publicKey: %v", err)
	}
	if pk.Len() != layout.PublicKeySize {
		t.Errorf("the peer's key exchange gave %d bytes, its layout wants %d",
			pk.Len(), layout.PublicKeySize)
	}

	// The hash is NOT: the message struct's MAC fields are SHA-256 sized.
	var msg MessageInitiation
	msg.Type = MessageInitiationType
	msg.Ephemeral = pk.wireArray()
	if got := len(msg.MAC1); got == layout.MACSize {
		t.Fatalf("the message's MAC field is %d bytes, matching the SHA-384 layout; "+
			"hash dispatch appears to have landed, so replace this test with a real "+
			"two-suite handshake", got)
	}
	if _, err := layout.AppendInitiation(nil, msg.toWire()); !errors.Is(err, wire.ErrFieldLength) {
		t.Errorf("encoding error = %v, want %v; MACs of the wrong size for the suite "+
			"must not be encodable", err, wire.ErrFieldLength)
	}
	t.Logf("message MAC field %d bytes, SHA-384 layout wants %d", len(msg.MAC1), layout.MACSize)

	hardcoded := countHandshakeHardcodedCrypto(t)
	if hardcoded == 0 {
		t.Error("noise-protocol.go no longer calls wolfCrypt directly, so dispatch " +
			"appears complete: replace this test with an end-to-end two-suite handshake")
	}
	t.Logf("noise-protocol.go still has %d direct wolfCrypt hash/AEAD calls", hardcoded)
}

// countHandshakeHardcodedCrypto counts the direct wolfCrypt hash and AEAD calls
// left in the handshake, which is the remaining dispatch work.
func countHandshakeHardcodedCrypto(t *testing.T) int {
	t.Helper()
	src, err := os.ReadFile("noise-protocol.go")
	if err != nil {
		t.Fatalf("reading noise-protocol.go: %v", err)
	}
	n := 0
	for _, pat := range []string{"Wc_Sha256", "Wc_AesGcm"} {
		n += bytes.Count(src, []byte(pat))
	}
	return n
}
