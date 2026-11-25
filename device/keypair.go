/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/cipher"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/replay"
)

/* Due to limitations in Go and /x/crypto there is currently
 * no way to ensure that key material is securely ereased in memory.
 *
 * Since this may harm the forward secrecy property,
 * we plan to resolve this issue; whenever Go allows us to do so.
 */

// Keypair is one session's transport state.
//
// send and receive are the constructed AEADs rather than raw keys, so the
// transport phase uses the cipher its suite names instead of a hardcoded one.
// They also carry their own nonce and tag lengths, which the data path needs
// per packet and which a key cannot tell it.
//
// Holding the AEAD rather than the key is safe to share across the encryption
// and decryption workers: every registered implementation keeps only immutable
// state, building its cipher context per operation, which is what cipher.AEAD
// implementations are expected to do. It also costs nothing, since the context
// was already being built per packet.
type Keypair struct {
	sendNonce    atomic.Uint64
	send         cipher.AEAD
	receive      cipher.AEAD
	replayFilter replay.Filter
	isInitiator  bool
	created      time.Time
	localIndex   uint32
	remoteIndex  uint32
}

type Keypairs struct {
	sync.RWMutex
	current  *Keypair
	previous *Keypair
	next     atomic.Pointer[Keypair]
}

func (kp *Keypairs) Current() *Keypair {
	kp.RLock()
	defer kp.RUnlock()
	return kp.current
}

func (device *Device) DeleteKeypair(key *Keypair) {
	if key != nil {
		device.indexTable.Delete(key.localIndex)
	}
}
