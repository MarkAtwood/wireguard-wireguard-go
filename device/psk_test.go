/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2026 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"testing"
)

/* The preshared key is wolfGuard's only post-quantum confidentiality mode
 * today, and the only one that needs no new wire format: the psk2 in
 * Noise_IKpsk2 is 32 symmetric bytes mixed into the chain, so an adversary who
 * recovers every Diffie-Hellman value, which a quantum computer eventually
 * does, still cannot derive the session key without it.
 *
 * That makes one property security-relevant above all others: a peer pair whose
 * preshared keys disagree must FAIL to handshake. An implementation that
 * ignored a configured key, or quietly treated a mismatch as no key, would
 * leave the mode looking enabled while providing nothing, and a fleet would
 * believe it had post-quantum confidentiality it did not have. That is the
 * failure these tests exist to catch, so each negative case is paired with the
 * positive that differs from it only in the key.
 */

// pskOf returns a distinct, non-zero preshared key. The value is arbitrary.
// What matters is that it is not all zeros, since unset means 32 zero bytes and
// a test keyed on zeros would pass against an implementation that ignored the
// field entirely.
func pskOf(b byte) NoisePresharedKey {
	var psk NoisePresharedKey
	for i := range psk {
		psk[i] = b
	}
	return psk
}

// setPSK installs a preshared key on a peer, taking the handshake lock the way
// the UAPI path does.
func setPSK(tb testing.TB, peer *Peer, psk NoisePresharedKey) {
	tb.Helper()
	peer.handshake.mutex.Lock()
	peer.handshake.presharedKey = psk
	peer.handshake.mutex.Unlock()
}

// pskHandshakeSucceeds builds two devices that know each other, optionally
// installing a preshared key on each side, runs a complete handshake, and
// reports whether it completed.
//
// Cleanup goes through t.Cleanup rather than returned values, because every
// caller wants only the verdict.
func pskHandshakeSucceeds(t *testing.T, initiatorPSK, responderPSK *NoisePresharedKey) bool {
	t.Helper()

	responder := randDevice(t)
	t.Cleanup(responder.Close)
	initiator := randDevice(t)
	t.Cleanup(initiator.Close)

	peerOfInitiator, err := responder.NewPeer(initiator.staticIdentity.privateKey.publicKeyOrFatal(t))
	if err != nil {
		t.Fatal(err)
	}
	peerOfResponder, err := initiator.NewPeer(responder.staticIdentity.privateKey.publicKeyOrFatal(t))
	if err != nil {
		t.Fatal(err)
	}

	/* The responder's view of the initiator carries the responder's key, and
	 * the initiator's view of the responder carries the initiator's. Setting
	 * them on the wrong peer would make a mismatch test pass for the wrong
	 * reason. */
	if responderPSK != nil {
		setPSK(t, peerOfInitiator, *responderPSK)
	}
	if initiatorPSK != nil {
		setPSK(t, peerOfResponder, *initiatorPSK)
	}

	peerOfInitiator.Start()
	peerOfResponder.Start()
	t.Cleanup(peerOfInitiator.Stop)
	t.Cleanup(peerOfResponder.Stop)

	/* The handshake has to run to the END of the response, not just the
	 * initiation. psk2 names the position: the preshared key is mixed in
	 * CreateMessageResponse and ConsumeMessageResponse, so the initiation
	 * never touches it and a test that stopped there would report success for
	 * every key, agreeing or not. */
	consumed := initiateOnce(t, initiator, responder, peerOfResponder)
	if consumed == nil {
		t.Fatal("the responder rejected the initiation, which the preshared key " +
			"cannot cause, so something else about the pair is wrong")
	}

	msg2, err := responder.CreateMessageResponse(consumed)
	if err != nil {
		/* The responder mixes the key while building the response, so a
		 * disagreement cannot show up here either: it only bites when the
		 * initiator opens the result. */
		t.Fatalf("CreateMessageResponse: %v", err)
	}
	respSuite, respLayout := consumed.handshake.suiteInForce()
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
	decodedResp, err := backLayout.ParseResponse(respPacket)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	return initiator.ConsumeMessageResponse(backSuite, decodedResp) != nil
}

// TestPresharedKeyAgreementGatesTheHandshake is the whole property in one
// table: the handshake completes exactly when the two sides hold the same key.
//
// The no-key row is the control. Without it, an implementation that rejected
// every handshake would pass all three negative rows.
//
// The rows are not interchangeable, which is worth knowing before anyone prunes
// the table. Mutating ConsumeMessageResponse to ignore the configured key is
// caught by exactly two of them: "both sides hold the same one", which then
// fails because the responder still mixes the key the initiator now drops, and
// "only the initiator has one", which then SUCCEEDS because both sides end up
// mixing zeros. The two rows where the sides disagree still fail under that
// mutation, for the wrong reason, so they catch nothing on their own.
func TestPresharedKeyAgreementGatesTheHandshake(t *testing.T) {
	a := pskOf(0x01)
	b := pskOf(0x02)

	for _, tt := range []struct {
		name      string
		initiator *NoisePresharedKey
		responder *NoisePresharedKey
		want      bool
	}{
		{"neither side has one", nil, nil, true},
		{"both sides hold the same one", &a, &a, true},
		{"the two disagree", &a, &b, false},
		{"only the responder has one", nil, &a, false},
		{"only the initiator has one", &a, nil, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := pskHandshakeSucceeds(t, tt.initiator, tt.responder); got != tt.want {
				if tt.want {
					t.Error("the handshake failed, so a key both sides agree on is not usable")
				} else {
					t.Error("the handshake completed, so the preshared key is not gating it " +
						"and the post-quantum mode is decoration")
				}
			}
		})
	}
}
