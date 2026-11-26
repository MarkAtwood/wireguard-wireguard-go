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

	"golang.org/x/crypto/chacha20poly1305"
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
		t.Fatal("the two suites do not differ in length, which this demo relies on for step 3")
	}

	// 2. Both are accepted, and each resolves to its own suite and layout from
	//    what actually arrives: the legacy suite from its length, being one of
	//    the two frozen nameless constructions, and SHA-384 from the name it
	//    carries. This is what the receive path does before it knows which peer
	//    is sending.
	for _, c := range []struct {
		name   string
		suite  *suite.Suite
		layout wire.Layout
	}{
		{"legacy", legacy, legacyLayout},
		{"sha384", sha384, sha384Layout},
	} {
		t.Run("resolves "+c.name, func(t *testing.T) {
			packet := withWireName(t, c.suite, make([]byte, c.layout.InitiationSize()))
			if !device.acceptsInitiationSize(len(packet)) {
				t.Fatalf("device rejects a %d byte initiation", len(packet))
			}
			gotSuite, gotLayout, body, ok := device.suiteForInitiation(packet)
			if !ok {
				t.Fatalf("no suite resolved for a %d byte initiation", len(packet))
			}
			if gotSuite != c.suite {
				t.Errorf("resolved to %q, want %q", gotSuite.Name(), c.suite.Name())
			}
			if gotLayout != c.layout {
				t.Errorf("resolved to %+v, want %+v", gotLayout, c.layout)
			}
			if len(body) != c.layout.InitiationSize() {
				t.Errorf("the body handed on is %d bytes, the layout says %d",
					len(body), c.layout.InitiationSize())
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

	/* 5. The receive buffer has to fit the larger of the two as it arrives,
	 *    which for the named suite means its name and length byte after the
	 *    MACs. Sizing from the layout alone would truncate every SHA-384
	 *    initiation by the length of its own name. */
	want := sha384Layout.InitiationSize() + len(sha384SuiteName) + 1
	if got := device.maxHandshakeSize(); got != want {
		t.Errorf("maxHandshakeSize = %d, want %d (the larger of the two, framed with its name)", got, want)
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

	named := withWireName(t, sendSuite, packet)

	recvSuite, recvLayout, body, ok := responder.suiteForInitiation(named)
	if !ok {
		t.Fatalf("the responder resolved no suite for a %d byte initiation", len(named))
	}
	if !responder.cookieChecker.CheckMAC1(recvSuite, body) {
		t.Fatal("the responder rejected mac1 on the initiation")
	}
	decoded, err := recvLayout.ParseInitiation(body)
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

	backSuite, backLayout, ok := initiator.suiteForResponsePacket(respPacket)
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
	/* The data phase, both directions, through whatever AEAD this suite named.
	 * Comparing key bytes is no longer possible, or interesting: the keypair
	 * holds a cipher, and what matters is that traffic survives the trip under
	 * the nonce layout the workers use. */
	transportRoundTrip(t, initiatorKeys, responderKeys, 0, []byte("initiator to responder"))
	transportRoundTrip(t, responderKeys, initiatorKeys, 1, []byte("responder to initiator"))

	/* The handshake's layout and the transport cipher have to agree on the tag
	 * length, since the receive worker trims exactly that many bytes. */
	if got, want := initiatorKeys.send.Overhead(), recvLayout.AEADOverhead; got != want {
		t.Errorf("the transport tag is %d bytes, the suite's layout says %d", got, want)
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

// chachaSuiteName is a suite whose transport cipher is not the deployed one.
// Its nonce is 12 bytes against AES-GCM's 16, which is the only pair of AEADs
// available here that makes the data path's nonce handling observable.
//
// It names SHA-384 so its messages differ in length from the legacy suite's and
// the two can be accepted together.
const chachaSuiteName = ":P-256:HKDF-SHA-384:AEAD_CHACHA20_POLY1305"

// TestTransportIsDrivenByTheSuitesAEAD is the data-plane counterpart of
// TestTwoSuitesHandshakeEndToEnd.
//
// The handshake being agile is not worth much on its own: before this, the
// transport phase called wolfCrypt AES-GCM directly with a 16-byte nonce, so
// every suite's traffic was encrypted with the same cipher whatever its name
// said. This runs a full handshake and then real traffic under a suite whose
// AEAD differs from the deployed one in both algorithm and nonce length.
func TestTransportIsDrivenByTheSuitesAEAD(t *testing.T) {
	registerChaCha20ForTest(t)

	responder := randDevice(t)
	defer responder.Close()
	initiator := randDevice(t)
	defer initiator.Close()

	// The responder serves the deployed suite and the ChaCha20 one at once,
	// which is the mid-migration state. The initiator accepts it too, since it
	// has to route the response back by length.
	chachaOnResponder, err := responder.AcceptSuite([]byte(chachaSuiteName), []byte(LegacyIdentifier))
	if err != nil {
		t.Fatalf("the responder could not accept the ChaCha20 suite: %v", err)
	}
	chachaOnInitiator, err := initiator.AcceptSuite([]byte(chachaSuiteName), []byte(LegacyIdentifier))
	if err != nil {
		t.Fatalf("the initiator could not accept the ChaCha20 suite: %v", err)
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

	if err := peerOfResponder.SetSuite(chachaOnInitiator); err != nil {
		t.Fatalf("SetSuite: %v", err)
	}

	// The handshake and a transport round trip in both directions, which
	// exchange does, all under ChaCha20-Poly1305.
	used := exchange(t, initiator, responder, peerOfResponder, peerOfInitiator)
	if used != chachaOnResponder {
		t.Fatalf("the handshake ran under %q, want %q", used.Name(), chachaOnResponder.Name())
	}

	// The session really is carrying ChaCha20-Poly1305, not AES-GCM wearing
	// its name.
	session := peerOfResponder.keypairs.current
	if session == nil {
		t.Fatal("no session keypair")
	}
	if got := session.send.NonceSize(); got != chacha20poly1305.NonceSize {
		t.Errorf("the transport nonce is %d bytes, ChaCha20-Poly1305 takes %d", got, chacha20poly1305.NonceSize)
	}
	if got := session.send.Overhead(); got != chacha20poly1305.Overhead {
		t.Errorf("the transport tag is %d bytes, ChaCha20-Poly1305 produces %d", got, chacha20poly1305.Overhead)
	}

	// And the deployed suite's nonce is a different length, so neither the
	// workers nor this test can be assuming one of them.
	legacy, _ := responder.localSuite()
	legacyAEAD, err := legacy.NewAEAD(make([]byte, legacy.AEADKeySize))
	if err != nil {
		t.Fatalf("constructing the legacy aead: %v", err)
	}
	if legacyAEAD.NonceSize() == session.send.NonceSize() {
		t.Fatalf("both suites use a %d byte nonce, so this test proves nothing", legacyAEAD.NonceSize())
	}
	t.Logf("deployed suite nonce %d bytes, ChaCha20 suite nonce %d bytes",
		legacyAEAD.NonceSize(), session.send.NonceSize())

	// Both nonce lengths have to satisfy the bounds the buffers are sized
	// from, which is what checkTransportAEAD enforces per session.
	for _, a := range []struct {
		name string
		aead interface {
			NonceSize() int
			Overhead() int
		}
	}{{"legacy", legacyAEAD}, {"chacha20", session.send}} {
		if a.aead.NonceSize() < MinTransportNonceSize || a.aead.NonceSize() > MaxTransportNonceSize {
			t.Errorf("%s nonce %d is outside the transport bounds %d..%d",
				a.name, a.aead.NonceSize(), MinTransportNonceSize, MaxTransportNonceSize)
		}
		if a.aead.Overhead() < MinTransportOverhead || a.aead.Overhead() > MaxTransportOverhead {
			t.Errorf("%s tag %d is outside the transport bounds %d..%d",
				a.name, a.aead.Overhead(), MinTransportOverhead, MaxTransportOverhead)
		}
	}
}

// TestTwoDevicePingUnderChaCha20 drives the real data path under a suite whose
// transport nonce is 12 bytes rather than the deployed 16.
//
// TestTwoDevicePing covers the same route under AES-GCM, and
// TestTransportIsDrivenByTheSuitesAEAD covers the ciphers directly. Neither of
// those goes through RoutineEncryption and RoutineDecryption, which is where
// the nonce is built per packet from a buffer shared across packets. This is
// the only test that would catch that buffer being sliced to a fixed length or
// the counter being written at the wrong offset, so it is the one that earns
// its keep.
//
// The suite is pinned before any traffic flows, so the first ping negotiates
// it rather than renegotiating an existing session.
func TestTwoDevicePingUnderChaCha20(t *testing.T) {
	registerChaCha20ForTest(t)
	goroutineLeakCheck(t)
	pair := genTestPair(t, true)

	for i := range pair {
		dev := pair[i].dev

		s, err := dev.AcceptSuite([]byte(chachaSuiteName), []byte(LegacyIdentifier))
		if err != nil {
			t.Fatalf("device %d could not accept the ChaCha20 suite: %v", i, err)
		}

		dev.peers.RLock()
		peers := make([]*Peer, 0, len(dev.peers.keyMap))
		for _, p := range dev.peers.keyMap {
			peers = append(peers, p)
		}
		dev.peers.RUnlock()

		if len(peers) == 0 {
			t.Fatalf("device %d has no peers to move", i)
		}
		for _, p := range peers {
			if err := p.SetSuite(s); err != nil {
				t.Fatalf("device %d: SetSuite: %v", i, err)
			}
		}
	}

	t.Run("ping 1.0.0.1", func(t *testing.T) {
		pair.Send(t, Ping, nil)
	})
	t.Run("ping 1.0.0.2", func(t *testing.T) {
		pair.Send(t, Pong, nil)
	})
}
