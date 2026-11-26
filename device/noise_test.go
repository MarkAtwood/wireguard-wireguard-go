/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/suite"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"golang.zx2c4.com/wireguard/wire"
)

func TestCurveWrappers(t *testing.T) {
	sk1, err := newPrivateKey(testKEX())
	assertNil(t, err)

	sk2, err := newPrivateKey(testKEX())
	assertNil(t, err)

	pk1 := sk1.publicKeyOrFatal(t)
	pk2 := sk2.publicKeyOrFatal(t)

	ss1, err1 := sk1.sharedSecret(testKEX(), pk2)
	ss2, err2 := sk2.sharedSecret(testKEX(), pk1)

	if err1 != nil || err2 != nil {
		t.Fatalf("Failed to compute shared secret: %v, %v", err1, err2)
	}
	if !bytes.Equal(ss1, ss2) {
		t.Fatalf("the two directions disagree: %x and %x", ss1, ss2)
	}
	if len(ss1) == 0 {
		t.Fatal("the shared secret is empty")
	}
}

func randDevice(t *testing.T) *Device {
	sk, err := newPrivateKey(testKEX())
	if err != nil {
		t.Fatal(err)
	}
	tun := tuntest.NewChannelTUN()
	logger := NewLogger(LogLevelError, "")
	device := NewDevice(tun.TUN(), conn.NewDefaultBind(), logger)
	device.SetPrivateKey(sk)
	return device
}

func assertNil(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func assertEqual(t *testing.T, a, b []byte) {
	if !bytes.Equal(a, b) {
		t.Fatal(a, "!=", b)
	}
}

func TestNoiseHandshake(t *testing.T) {
	dev1 := randDevice(t)
	dev2 := randDevice(t)

	defer dev1.Close()
	defer dev2.Close()

	peer1, err := dev2.NewPeer(dev1.staticIdentity.privateKey.publicKeyOrFatal(t))
	if err != nil {
		t.Fatal(err)
	}
	peer2, err := dev1.NewPeer(dev2.staticIdentity.privateKey.publicKeyOrFatal(t))
	if err != nil {
		t.Fatal(err)
	}
	peer1.Start()
	peer2.Start()

	assertEqual(
		t,
		peer1.handshake.precomputedStaticStatic[:],
		peer2.handshake.precomputedStaticStatic[:],
	)

	/* simulate handshake */

	// initiation message

	t.Log("exchange initiation message")

	msg1, err := dev1.CreateMessageInitiation(peer2)
	assertNil(t, err)

	/* The initiation goes over the wire and comes back off it, resolved the way
	 * the receive path resolves it: from the name the packet carries, before
	 * anything about it is authenticated. Handing the in-memory message
	 * straight to the responder would skip the encoding, which is where a
	 * field whose length does not match its suite would be caught. */
	sendSuite, sendLayout := peer2.handshake.suiteInForce()
	packet, err := sendLayout.AppendInitiation(nil, msg1)
	assertNil(t, err)
	packet = withWireName(t, sendSuite, packet)

	recvSuite, recvLayout, body, ok := dev2.suiteForInitiation(packet)
	if !ok {
		t.Fatalf("dev2 resolved no suite for a %d byte initiation", len(packet))
	}
	decoded, err := recvLayout.ParseInitiation(body)
	assertNil(t, err)

	peer := dev2.ConsumeMessageInitiation(recvSuite, decoded)
	if peer == nil {
		t.Fatal("handshake failed at initiation message")
	}

	assertEqual(
		t,
		peer1.handshake.chainKey,
		peer2.handshake.chainKey,
	)

	assertEqual(
		t,
		peer1.handshake.hash,
		peer2.handshake.hash,
	)

	// response message

	t.Log("exchange response message")

	msg2, err := dev2.CreateMessageResponse(peer1)
	assertNil(t, err)

	_, respLayout := peer1.handshake.suiteInForce()
	respPacket, err := respLayout.AppendResponse(nil, msg2)
	assertNil(t, err)

	respSuite, respRecvLayout, ok := dev1.suiteForResponsePacket(respPacket)
	if !ok {
		t.Fatalf("dev1 accepts no suite framing a %d byte response", len(respPacket))
	}
	decodedResp, err := respRecvLayout.ParseResponse(respPacket)
	assertNil(t, err)

	peer = dev1.ConsumeMessageResponse(respSuite, decodedResp)
	if peer == nil {
		t.Fatal("handshake failed at response message")
	}

	assertEqual(
		t,
		peer1.handshake.chainKey,
		peer2.handshake.chainKey,
	)

	assertEqual(
		t,
		peer1.handshake.hash,
		peer2.handshake.hash,
	)

	// key pairs

	t.Log("deriving keys")

	err = peer1.BeginSymmetricSession()
	if err != nil {
		t.Fatal("failed to derive keypair for peer 1", err)
	}

	err = peer2.BeginSymmetricSession()
	if err != nil {
		t.Fatal("failed to derive keypair for peer 2", err)
	}

	key1 := peer1.keypairs.next.Load()
	key2 := peer2.keypairs.current

	// encrypting / decryption test

	t.Log("test the transport phase")

	/* Both directions through the session's own AEADs. This used to call
	 * wolfCrypt AES-GCM directly with keypair.send as a key; the keypair holds
	 * the suite's cipher now, so the transport phase is exercised through the
	 * same objects the data path uses. */
	transportRoundTrip(t, key2, key1, 0, []byte("wireguard test message 1"))
	transportRoundTrip(t, key1, key2, 1, []byte("wireguard test message 2"))
}

// withWireName appends the handshake name the way SendHandshakeInitiation does,
// for tests that build an initiation themselves and then resolve it.
//
// A test that skipped this would be handing the receive path a packet no peer
// would send: for a named suite, resolution reads the name off the tail, so an
// initiation without one is either unresolvable or mistaken for a nameless
// suite of that length. The two frozen constructions send no name and are
// returned unchanged.
func withWireName(tb testing.TB, s *suite.Suite, packet []byte) []byte {
	tb.Helper()
	name := string(s.Name())
	if !carriesWireName(name) {
		return packet
	}
	out, err := wire.AppendNameTail(packet, []byte(name))
	if err != nil {
		tb.Fatalf("AppendNameTail(%q): %v", name, err)
	}
	return out
}
