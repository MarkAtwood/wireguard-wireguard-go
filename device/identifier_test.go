/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"strings"
	"testing"
)

// otherIdentifier is a second fleet's identifier. Nothing about its value
// matters beyond being different from the deployment constant.
const otherIdentifier = "WolfGuard test fleet two"

// initiateOnce runs the initiation leg the way the receive path runs it and
// returns the peer the responder attributed it to, or nil.
//
// It differs from exchange in not failing the test when the responder rejects
// the initiation, because a rejection is the expected outcome of half of what
// this file tests.
func initiateOnce(t *testing.T, initiator, responder *Device, peerOfResponder *Peer) *Peer {
	t.Helper()

	msg, err := initiator.CreateMessageInitiation(peerOfResponder)
	if err != nil {
		t.Fatalf("CreateMessageInitiation: %v", err)
	}
	sendSuite, sendLayout := peerOfResponder.handshake.suiteInForce()
	packet, err := sendLayout.AppendInitiation(nil, msg)
	if err != nil {
		t.Fatalf("AppendInitiation: %v", err)
	}
	if err := peerOfResponder.cookieGenerator.AddMacs(sendSuite, packet); err != nil {
		t.Fatalf("AddMacs: %v", err)
	}

	recvSuite, recvLayout, ok := responder.suiteForInitiationSize(len(packet))
	if !ok {
		t.Fatalf("the responder accepts no suite framing a %d byte initiation", len(packet))
	}

	/* mac1 is keyed on the responder's static public key and has no identifier
	 * in it, so it has to verify whichever identifier the transcript was begun
	 * under. Asserting it here is what localises a failure below to the
	 * transcript rather than to the cookie MACs. */
	if !responder.cookieChecker.CheckMAC1(recvSuite, packet) {
		t.Fatal("the responder rejected mac1, so the identifier reached the cookie keys")
	}

	decoded, err := recvLayout.ParseInitiation(packet)
	if err != nil {
		t.Fatalf("ParseInitiation: %v", err)
	}
	return responder.ConsumeMessageInitiation(recvSuite, decoded)
}

// TestPerPeerIdentifierReachesTheTranscript is both halves of the identifier at
// once, with the handshake as the oracle.
//
// The identifier in force for a handshake is the responder's. A responder has
// to know it before it knows who is speaking, since Hash is
// H(ChainKey || identifier) and that hash is the additional data for the AEAD
// that opens encrypted_static, from which the peer is identified. So a
// responder uses one of its own, and an initiator has to be told which one each
// of its peers answers under.
//
// The negative and the positive are the same handshake, differing only in
// whether the initiator was told. Without the pair, the failure could be any of
// a dozen things.
func TestPerPeerIdentifierReachesTheTranscript(t *testing.T) {
	responder := randDevice(t)
	defer responder.Close()
	initiator := randDevice(t)
	defer initiator.Close()

	// The device half: the responder answers under an identifier of its own,
	// which re-derives the initial state of every suite it accepts.
	if err := responder.SetIdentifier([]byte(otherIdentifier)); err != nil {
		t.Fatalf("SetIdentifier: %v", err)
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

	if consumed := initiateOnce(t, initiator, responder, peerOfResponder); consumed != nil {
		t.Fatal("the responder accepted an initiation begun under the wrong identifier")
	}

	// The peer half: told what its far end answers under, the initiator begins
	// the transcript with it and the same handshake completes.
	if err := peerOfResponder.SetIdentifier([]byte(otherIdentifier)); err != nil {
		t.Fatalf("peer SetIdentifier: %v", err)
	}
	consumed := initiateOnce(t, initiator, responder, peerOfResponder)
	if consumed == nil {
		t.Fatal("the responder rejected an initiation begun under its own identifier")
	}
	if consumed != peerOfInitiator {
		t.Fatal("the initiation was attributed to the wrong peer")
	}
}

// TestUnsetPeerIdentifierLeavesTheDeployedStateAlone is why none of this moves
// a byte for anything in the field.
//
// A peer with no identifier of its own shares the device's, and the suite in
// force already carries the state derived from it, so the initiator path
// returns that state rather than re-deriving an equal one.
func TestUnsetPeerIdentifierLeavesTheDeployedStateAlone(t *testing.T) {
	device := randDevice(t)
	defer device.Close()

	peer, err := device.NewPeer(newTestPublicKey(t))
	if err != nil {
		t.Fatal(err)
	}

	s, _ := device.localSuite()
	st, err := peer.initialState(s)
	if err != nil {
		t.Fatalf("initialState: %v", err)
	}
	if !bytes.Equal(st.ChainKey, s.State.ChainKey) || !bytes.Equal(st.Hash, s.State.Hash) {
		t.Error("an unconfigured peer does not begin from the suite's own initial state")
	}

	/* And once configured with the identifier it was already using, the state
	 * has to come out the same, which is what says the derivation and the
	 * precomputation agree. */
	if err := peer.SetIdentifier([]byte(LegacyIdentifier)); err != nil {
		t.Fatalf("SetIdentifier: %v", err)
	}
	again, err := peer.initialState(s)
	if err != nil {
		t.Fatalf("initialState: %v", err)
	}
	if !bytes.Equal(again.ChainKey, s.State.ChainKey) || !bytes.Equal(again.Hash, s.State.Hash) {
		t.Error("deriving under the deployment identifier disagrees with the precomputed state")
	}
}

// TestSetIdentifierRedereivesTheAcceptSet covers the device half on its own: it
// is not enough to record the identifier, every accepted suite's initial state
// has to move with it.
func TestSetIdentifierRederivesTheAcceptSet(t *testing.T) {
	device := randDevice(t)
	defer device.Close()

	second, err := device.AcceptSuite([]byte(sha384SuiteName), []byte(LegacyIdentifier))
	if err != nil {
		t.Fatalf("AcceptSuite: %v", err)
	}
	local, _ := device.localSuite()

	beforeLocal := bytes.Clone(local.State.Hash)
	beforeSecond := bytes.Clone(second.State.Hash)

	if err := device.SetIdentifier([]byte(otherIdentifier)); err != nil {
		t.Fatalf("SetIdentifier: %v", err)
	}

	if bytes.Equal(local.State.Hash, beforeLocal) {
		t.Error("the local suite's initial state did not move with the identifier")
	}
	if bytes.Equal(second.State.Hash, beforeSecond) {
		t.Error("the second accepted suite's initial state did not move with the identifier")
	}

	/* The chain key is H(name) and has no identifier in it, so it must not
	 * move. If it did, the identifier would be separating keys rather than
	 * only the transcript, and the AEAD key would change with it. */
	if _, err := device.AcceptSuite([]byte(sha384SuiteName), []byte(otherIdentifier)); err != nil {
		t.Fatalf("re-accepting: %v", err)
	}
	if got, want := device.deviceIdentifier(), []byte(otherIdentifier); !bytes.Equal(got, want) {
		t.Errorf("deviceIdentifier = %q, want %q", got, want)
	}

	// The suite instances must be the same pointers, since a handshake and a
	// pinned peer both identify a suite by pointer.
	nowLocal, _ := device.localSuite()
	if nowLocal != local {
		t.Error("the local suite was replaced rather than re-derived in place")
	}

	if err := device.SetIdentifier(nil); err == nil {
		t.Error("an empty identifier was accepted")
	}
}

// TestUAPIRoundTripsIdentifiers checks the configuration surface, including the
// order the lines come back in: the identifier has to precede the accept set,
// because accepting a suite derives its state from the identifier in force.
func TestUAPIRoundTripsIdentifiers(t *testing.T) {
	device := randDevice(t)
	defer device.Close()

	peerKey := newTestPublicKey(t)
	conf := uapiCfg(
		"identifier", otherIdentifier,
		"accept_suite", sha384SuiteName,
	) + peerLine(t, peerKey, "identifier="+otherIdentifier)

	if err := device.IpcSet(conf); err != nil {
		t.Fatalf("IpcSet: %v", err)
	}

	var out bytes.Buffer
	if err := device.IpcGetOperation(&out); err != nil {
		t.Fatalf("IpcGetOperation: %v", err)
	}
	got := out.String()

	wantDevice := "identifier=" + otherIdentifier
	if !strings.Contains(got, wantDevice) {
		t.Errorf("the configuration does not report %q\n%s", wantDevice, got)
	}

	idAt := strings.Index(got, "identifier="+otherIdentifier)
	acceptAt := strings.Index(got, "accept_suite=")
	if idAt < 0 || acceptAt < 0 || idAt > acceptAt {
		t.Errorf("the identifier is reported at %d and the accept set at %d; the identifier has to come first or a re-applied configuration derives the wrong state", idAt, acceptAt)
	}

	// The peer's identifier is reported too, and only because it was set.
	if strings.Count(got, "identifier="+otherIdentifier) != 2 {
		t.Errorf("want the identifier reported once for the device and once for the peer, got %d occurrences\n%s",
			strings.Count(got, "identifier="+otherIdentifier), got)
	}

	/* A peer that was never given one must report nothing, or reading the
	 * configuration back would turn the default into a pin. */
	plain := randDevice(t)
	defer plain.Close()
	if _, err := plain.NewPeer(newTestPublicKey(t)); err != nil {
		t.Fatal(err)
	}
	var plainOut bytes.Buffer
	if err := plain.IpcGetOperation(&plainOut); err != nil {
		t.Fatalf("IpcGetOperation: %v", err)
	}
	/* One occurrence only: the device's. The peer contributes none. */
	if n := strings.Count(plainOut.String(), "identifier="); n != 1 {
		t.Errorf("want only the device's identifier reported, got %d occurrences\n%s", n, plainOut.String())
	}

	if err := device.IpcSet(peerLine(t, peerKey, "identifier=")); err == nil {
		t.Error("an empty peer identifier was accepted")
	}
}
