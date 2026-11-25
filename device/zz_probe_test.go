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
	"strings"
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

// TestPrimitivesAreDispatchedButBuffersAreFixed records exactly what is done
// and what is not, so the gap is a failing-when-fixed assertion rather than a
// note someone has to remember.
//
// DONE: the handshake's primitives all come from the suite. The key exchange,
// the hash used by mixHash, the HMAC that HKDF is built from, and the AEAD are
// each taken from the suite in force, so a peer on a different suite really
// does use different cryptography. noise-protocol.go's only remaining direct
// wolfCrypt calls are in init(), computing the legacy globals, which exists
// before any suite does.
//
// NOT DONE: the buffers are still sized for SHA-256. Handshake.hash and
// chainKey are fixed 32-byte arrays, and the message structs' MAC, Static and
// Timestamp fields are fixed too. A suite naming SHA-384 therefore cannot run
// end to end: its layout wants 48-byte MACs and the message has 32.
//
// So the remaining work is sizing, not dispatch, which is the same structural
// problem the key fields had. When the buffers follow the suite, this test
// fails and whoever sees it should replace it with a real two-suite handshake.
func TestPrimitivesAreDispatchedButBuffersAreFixed(t *testing.T) {
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

	// Dispatch: the peer's suite supplies all four primitives, and they differ
	// from the device's where the suite says they should.
	if got := sha384.NewHash().Size(); got != 48 {
		t.Errorf("the SHA-384 suite's hash is %d bytes, want 48", got)
	}
	deviceSuite, _ := device.localSuite()
	if deviceSuite.NewHash().Size() == sha384.NewHash().Size() {
		t.Error("both suites report the same hash size; dispatch is not taking effect")
	}
	mac, err := sha384.NewHMAC([]byte("key"))
	if err != nil {
		t.Fatalf("the suite has no HMAC: %v", err)
	}
	if got := mac.Size(); got != 48 {
		t.Errorf("the suite's HMAC is %d bytes, want 48", got)
	}

	// Only init() still calls wolfCrypt directly in the handshake file.
	inHandshake := countDirectCryptoOutsideInit(t)
	if inHandshake != 0 {
		t.Errorf("noise-protocol.go makes %d direct wolfCrypt hash/AEAD calls outside init()", inHandshake)
	}

	// Sizing: the message's MAC field is still SHA-256 sized, so a SHA-384
	// suite cannot be encoded.
	var msg MessageInitiation
	if len(msg.MAC1) == layout.MACSize {
		t.Fatalf("the message's MAC field is %d bytes, matching the SHA-384 layout; "+
			"buffer sizing appears to have landed, so replace this test with a real "+
			"two-suite handshake", len(msg.MAC1))
	}
	t.Logf("message MAC field %d bytes, the SHA-384 layout wants %d", len(msg.MAC1), layout.MACSize)

	msg.Type = MessageInitiationType
	if _, err := layout.AppendInitiation(nil, msg.toWire()); !errors.Is(err, wire.ErrFieldLength) {
		t.Errorf("encoding error = %v, want %v", err, wire.ErrFieldLength)
	}
}

// countDirectCryptoOutsideInit counts direct wolfCrypt hash and AEAD calls in
// the handshake file, excluding init(), which computes the legacy globals
// before any suite exists.
func countDirectCryptoOutsideInit(t *testing.T) int {
	t.Helper()
	src, err := os.ReadFile("noise-protocol.go")
	if err != nil {
		t.Fatalf("reading noise-protocol.go: %v", err)
	}

	n := 0
	inInit := false
	for _, line := range strings.Split(string(src), "\n") {
		switch {
		case strings.HasPrefix(line, "func init() {"):
			inInit = true
			continue
		case inInit && line == "}":
			inInit = false
			continue
		}
		if inInit {
			continue
		}
		if strings.Contains(line, "Wc_Sha256") || strings.Contains(line, "Wc_AesGcm") {
			n++
		}
	}
	return n
}
