/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"sync"
	"testing"
	"time"
)

/* No test rekeyed a device while handshake work ran on the same peer, which is
 * why the race detector had never looked at the interaction. These are the lock
 * sequences that meet there:
 *
 *	SetPrivateKey            staticIdentity.Lock  then handshake.RLock
 *	CreateMessageInitiation  staticIdentity.RLock then handshake.Lock
 *	ConsumeMessageResponse   handshake.RLock      then staticIdentity.RLock
 *	ExpireCurrentKeypairs    handshake.Lock       and no identity lock at all
 *
 * The third takes the two in the opposite order from the first two. On its own
 * that is survivable, because the rekey only wants a read lock on the handshake
 * and two readers do not exclude each other. It stops being survivable when a
 * handshake writer that holds no identity lock is waiting, which is the fourth
 * line: a blocked writer makes sync.RWMutex hold off new readers, so the rekey
 * queues behind that writer, the writer waits for the reader that is consuming
 * a response, and that reader waits for the identity the rekey is holding.
 *
 * All four run here for that reason. A test with only the first three cannot
 * close the cycle.
 */

// rekeyRaceDuration is how long TestRekeyUnderHandshakeLoad hammers the device.
//
// It is a probe rather than a proof: a wrong lock order that never interleaves
// badly within the window passes. What makes the probe worth keeping is that
// the failure is unmistakable when it does land, a hang rather than a wrong
// answer, and that -race watches the shared handshake fields throughout.
const rekeyRaceDuration = 2 * time.Second

func TestRekeyUnderHandshakeLoad(t *testing.T) {
	device := randDevice(t)

	peerKey, err := newPrivateKey(testKEX())
	if err != nil {
		t.Fatal(err)
	}
	peer, err := device.NewPeer(peerKey.publicKeyOrFatal(t))
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}

	/* Two identities to alternate between. SetPrivateKey returns early when
	 * handed the key it already holds, so a single new key would rekey once and
	 * then do nothing. */
	var rekeys [2]NoisePrivateKey
	for i := range rekeys {
		k, err := newPrivateKey(testKEX())
		if err != nil {
			t.Fatal(err)
		}
		rekeys[i] = k
	}

	s, layout := device.localSuite()

	/* A response that gets past ConsumeMessageResponse's state and suite checks
	 * and so reaches the identity lock, which is the point of including it. It
	 * fails later, at the Diffie-Hellman, and a failed consume leaves the
	 * handshake state alone so the loop can keep using it. */
	response := &MessageResponse{
		Type:      MessageResponseType,
		Sender:    1,
		Ephemeral: randBytes(t, layout.PublicKeySize),
		Empty:     randBytes(t, layout.AEADOverhead),
		MAC1:      make([]byte, layout.MACSize),
		MAC2:      make([]byte, layout.MACSize),
	}

	// The index is handshake state, so the test reads it the way the rest of
	// the package does rather than racing on it itself.
	receiver := func() uint32 {
		peer.handshake.mutex.RLock()
		defer peer.handshake.mutex.RUnlock()
		return peer.handshake.localIndex
	}

	deadline := time.Now().Add(rekeyRaceDuration)
	var wg sync.WaitGroup
	run := func(f func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				f()
			}
		}()
	}

	run(func() {
		for i := range rekeys {
			if err := device.SetPrivateKey(rekeys[i]); err != nil {
				t.Errorf("SetPrivateKey: %v", err)
				return
			}
		}
	})
	run(func() {
		// Keeps the handshake in handshakeInitiationCreated, which is what
		// makes the consumer below reach the identity lock.
		device.CreateMessageInitiation(peer)
	})
	run(func() {
		r := receiver()
		if r == 0 {
			return
		}
		response.Receiver = r
		device.ConsumeMessageResponse(s, response)
	})
	run(func() {
		peer.ExpireCurrentKeypairs()
	})

	/* A deadlock shows up as this never returning. There is deliberately no
	 * watchdog: goroutines blocked on a mutex cannot be unwound, so a watchdog
	 * could only report and then block anyway, and the panic from go test's own
	 * -timeout discards buffered test output, which is how the first version of
	 * this test lost its message. The useful artifact is that panic's dump of
	 * every goroutine and the lock each one is waiting on, which names the
	 * cycle outright. */
	wg.Wait()
}
