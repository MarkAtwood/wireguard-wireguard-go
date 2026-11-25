/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/suite"
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

	// 2. Both are accepted, and each length routes to its own suite and layout.
	//    This is what the receive path does before it knows which peer is
	//    sending.
	for _, c := range []struct {
		name   string
		size   int
		suite  *suite.Suite
		layout wire.Layout
	}{
		{"legacy", legacyLayout.InitiationSize(), legacy, legacyLayout},
		{"sha384", sha384Layout.InitiationSize(), sha384, sha384Layout},
	} {
		t.Run("routes "+c.name, func(t *testing.T) {
			if !device.acceptsInitiationSize(c.size) {
				t.Fatalf("device rejects a %d byte initiation", c.size)
			}
			gotSuite, gotLayout, ok := device.suiteForInitiationSize(c.size)
			if !ok {
				t.Fatalf("no suite for a %d byte initiation", c.size)
			}
			if gotSuite != c.suite {
				t.Errorf("routed to %q, want %q", gotSuite.Name(), c.suite.Name())
			}
			if gotLayout != c.layout {
				t.Errorf("routed to %+v, want %+v", gotLayout, c.layout)
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

// exchange runs one complete handshake between two live devices, over encoded
// packets, and returns the suite the responder routed it to.
//
// It does what the receive path does rather than handing in-memory messages
// across: encode under the sender's layout, add the MACs to the encoded bytes,
// route the packet to a suite by its length alone, check mac1, parse, consume.
// Every length that the suite decides is therefore exercised, including the two
// that only the encoded form can get wrong, the MAC field offsets.
func exchange(t *testing.T, initiator, responder *Device, peerOfResponder, peerOfInitiator *Peer) *suite.Suite {
	t.Helper()

	// --- initiation, initiator to responder ---

	msg1, err := initiator.CreateMessageInitiation(peerOfResponder)
	if err != nil {
		t.Fatalf("CreateMessageInitiation: %v", err)
	}
	sendSuite, sendLayout := peerOfResponder.handshake.suiteInForce()
	packet, err := sendLayout.AppendInitiation(nil, msg1)
	if err != nil {
		t.Fatalf("AppendInitiation: %v", err)
	}
	if len(packet) != sendLayout.InitiationSize() {
		t.Fatalf("encoded initiation is %d bytes, the layout says %d", len(packet), sendLayout.InitiationSize())
	}
	if err := peerOfResponder.cookieGenerator.AddMacs(sendSuite, packet); err != nil {
		t.Fatalf("AddMacs: %v", err)
	}

	/* mac1 has to land on the field the codec reserved for it. That is the
	 * assertion the previous, hash-size-blind cookie code would have failed
	 * for SHA-384 while still interoperating with itself: it wrote mac1 at a
	 * fixed 32 bytes from the mac2 boundary regardless of the suite. mac2 is
	 * left zero because this generator holds no cookie. */
	mac1 := packet[sendLayout.InitiationMAC1Offset():sendLayout.InitiationMAC2Offset()]
	mac2 := packet[sendLayout.InitiationMAC2Offset():]
	if len(mac1) != sendLayout.MACSize || len(mac2) != sendLayout.MACSize {
		t.Fatalf("mac fields are %d and %d bytes, the layout says %d", len(mac1), len(mac2), sendLayout.MACSize)
	}
	if isZero(mac1) {
		t.Error("the mac1 field is still zero, so mac1 was written somewhere else")
	}
	if !isZero(mac2) {
		t.Error("the mac2 field is not zero, but no cookie has been issued")
	}

	recvSuite, recvLayout, ok := responder.suiteForInitiationSize(len(packet))
	if !ok {
		t.Fatalf("the responder accepts no suite framing a %d byte initiation", len(packet))
	}
	if !responder.cookieChecker.CheckMAC1(recvSuite, packet) {
		t.Fatal("the responder rejected mac1 on the initiation")
	}
	decoded, err := recvLayout.ParseInitiation(packet)
	if err != nil {
		t.Fatalf("ParseInitiation: %v", err)
	}
	consumed := responder.ConsumeMessageInitiation(recvSuite, decoded)
	if consumed == nil {
		t.Fatal("the responder rejected the initiation")
	}
	if consumed != peerOfInitiator {
		t.Fatal("the initiation was attributed to the wrong peer")
	}

	// --- response, responder to initiator ---

	msg2, err := responder.CreateMessageResponse(consumed)
	if err != nil {
		t.Fatalf("CreateMessageResponse: %v", err)
	}
	respSuite, respLayout := consumed.handshake.suiteInForce()
	if respSuite != recvSuite {
		t.Fatal("the responder answered in a different suite than it was asked in")
	}
	respPacket, err := respLayout.AppendResponse(nil, msg2)
	if err != nil {
		t.Fatalf("AppendResponse: %v", err)
	}
	if err := consumed.cookieGenerator.AddMacs(respSuite, respPacket); err != nil {
		t.Fatalf("AddMacs: %v", err)
	}

	backSuite, backLayout, ok := initiator.suiteForResponseSize(len(respPacket))
	if !ok {
		t.Fatalf("the initiator accepts no suite framing a %d byte response", len(respPacket))
	}
	if !initiator.cookieChecker.CheckMAC1(backSuite, respPacket) {
		t.Fatal("the initiator rejected mac1 on the response")
	}
	decodedResp, err := backLayout.ParseResponse(respPacket)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if initiator.ConsumeMessageResponse(backSuite, decodedResp) == nil {
		t.Fatal("the initiator rejected the response")
	}

	// --- both sides derive the same session ---

	if !bytes.Equal(peerOfResponder.handshake.chainKey, peerOfInitiator.handshake.chainKey) {
		t.Error("the two ends disagree on the chaining key")
	}
	if !bytes.Equal(peerOfResponder.handshake.hash, peerOfInitiator.handshake.hash) {
		t.Error("the two ends disagree on the transcript hash")
	}
	if got := len(peerOfResponder.handshake.hash); got != recvSuite.NewHash().Size() {
		t.Errorf("the transcript is %d bytes, the suite's hash is %d", got, recvSuite.NewHash().Size())
	}

	if err := peerOfResponder.BeginSymmetricSession(); err != nil {
		t.Fatalf("BeginSymmetricSession on the initiator: %v", err)
	}
	if err := peerOfInitiator.BeginSymmetricSession(); err != nil {
		t.Fatalf("BeginSymmetricSession on the responder: %v", err)
	}
	/* The initiator's peer object is the one on the initiating device, and an
	 * initiator installs its keypair as current while a responder installs
	 * the next one. */
	initiatorKeys := peerOfResponder.keypairs.current
	responderKeys := peerOfInitiator.keypairs.next.Load()
	if initiatorKeys == nil || responderKeys == nil {
		t.Fatal("a session keypair is missing")
	}
	if !bytes.Equal(initiatorKeys.send[:], responderKeys.receive[:]) {
		t.Error("the session send and receive keys do not match")
	}
	if isZero(initiatorKeys.send[:]) {
		t.Error("the session key is zero")
	}

	return recvSuite
}

// TestTwoSuitesHandshakeEndToEnd is the whole point of sizing the handshake
// from the suite: a device that accepts two suites completes a real handshake
// under each one, with different cryptography and different message lengths on
// the wire.
//
// Before the buffers followed the suite, the SHA-384 half of this could not
// run at all. The transcript and chaining key were fixed 32-byte arrays and the
// message's MAC fields were 32 bytes, so a layout wanting 48 could not be
// encoded. This test is what replaced the assertion that recorded that gap.
func TestTwoSuitesHandshakeEndToEnd(t *testing.T) {
	responder := randDevice(t)
	defer responder.Close()

	sha384Responder, err := responder.AcceptSuite([]byte(sha384SuiteName), []byte(LegacyIdentifier))
	if err != nil {
		t.Fatalf("the responder could not accept the SHA-384 suite: %v", err)
	}
	legacyResponder, _ := responder.localSuite()

	for _, c := range []struct {
		name string
		// pin is the suite the initiator is moved to, or nil to leave it on
		// the device's own.
		pin  *suite.Suite
		hash int
	}{
		{"legacy", nil, 32},
		{"sha384", sha384Responder, 48},
	} {
		t.Run(c.name, func(t *testing.T) {
			initiator := randDevice(t)
			defer initiator.Close()

			/* The initiator has to accept the suite too, since it must route
			 * the response back by length. */
			var pinned *suite.Suite
			if c.pin != nil {
				pinned, err = initiator.AcceptSuite([]byte(sha384SuiteName), []byte(LegacyIdentifier))
				if err != nil {
					t.Fatalf("the initiator could not accept the SHA-384 suite: %v", err)
				}
			}

			peerOfInitiator, err := responder.NewPeer(initiator.staticIdentity.privateKey.publicKeyOrFatal(t))
			if err != nil {
				t.Fatal(err)
			}
			peerOfResponder, err := initiator.NewPeer(responder.staticIdentity.privateKey.publicKeyOrFatal(t))
			if err != nil {
				t.Fatal(err)
			}
			peerOfInitiator.Start()
			peerOfResponder.Start()
			defer peerOfInitiator.Stop()
			defer peerOfResponder.Stop()

			if pinned != nil {
				if err := peerOfResponder.SetSuite(pinned); err != nil {
					t.Fatalf("SetSuite: %v", err)
				}
			}

			used := exchange(t, initiator, responder, peerOfResponder, peerOfInitiator)

			if got := used.NewHash().Size(); got != c.hash {
				t.Errorf("the handshake ran under a %d byte hash, want %d", got, c.hash)
			}
			if c.pin == nil && used != legacyResponder {
				t.Errorf("an unpinned peer's handshake ran under %q", used.Name())
			}
			if c.pin != nil && used != sha384Responder {
				t.Errorf("a pinned peer's handshake ran under %q", used.Name())
			}
		})
	}
}

// TestHandshakeFileCallsNoCryptoDirectly keeps the dispatch honest.
//
// Every primitive the handshake uses now comes from its suite. A direct
// wolfCrypt hash or AEAD call reappearing in noise-protocol.go would be an
// algorithm the suite's name does not describe, which is exactly what crypto
// agility here means.
func TestHandshakeFileCallsNoCryptoDirectly(t *testing.T) {
	src, err := os.ReadFile("noise-protocol.go")
	if err != nil {
		t.Fatalf("reading noise-protocol.go: %v", err)
	}
	for _, call := range []string{"Wc_Sha256", "Wc_Sha384", "Wc_Hmac", "Wc_AesGcm"} {
		if n := strings.Count(string(src), call); n != 0 {
			t.Errorf("noise-protocol.go makes %d direct %s call(s)", n, call)
		}
	}
}
