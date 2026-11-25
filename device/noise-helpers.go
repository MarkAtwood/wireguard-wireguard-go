/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"errors"
	"fmt"
	"golang.zx2c4.com/wireguard/suite"
	"hash"
)

/* KDF related functions.
 * HMAC-based Key Derivation Function (HKDF)
 * https://tools.ietf.org/html/rfc5869
 */

/* The key derivation below takes its MAC from the suite rather than calling
 * wolfCrypt with a hardcoded hash. The handshake's KDF is HKDF, and HKDF is
 * HMAC, so a suite that names SHA-384 must derive with HMAC-SHA-384 or its name
 * would not describe what produced the keys.
 *
 * Errors are reported rather than ignored: a MAC that failed to compute leaves
 * a zero buffer, and deriving a session key from zeros would be catastrophic
 * and silent.
 */

type hmacFunc func(key []byte) (hash.Hash, error)

func HMAC1(newHMAC hmacFunc, sum []byte, key, in0 []byte) error {
	h, err := newHMAC(key)
	if err != nil {
		return fmt.Errorf("keying hmac: %w", err)
	}
	if _, err := h.Write(in0); err != nil {
		return fmt.Errorf("hmac update: %w", err)
	}
	out := h.Sum(nil)
	if len(out) < len(sum) {
		return fmt.Errorf("hmac produced %d bytes, need %d: %w", len(out), len(sum), errKeySize)
	}
	copy(sum, out)
	return nil
}

func HMAC2(newHMAC hmacFunc, sum []byte, key, in0, in1 []byte) error {
	h, err := newHMAC(key)
	if err != nil {
		return fmt.Errorf("keying hmac: %w", err)
	}
	if _, err := h.Write(in0); err != nil {
		return fmt.Errorf("hmac update: %w", err)
	}
	if _, err := h.Write(in1); err != nil {
		return fmt.Errorf("hmac update: %w", err)
	}
	out := h.Sum(nil)
	if len(out) < len(sum) {
		return fmt.Errorf("hmac produced %d bytes, need %d: %w", len(out), len(sum), errKeySize)
	}
	copy(sum, out)
	return nil
}

func KDF1(newHMAC hmacFunc, t0 []byte, key, input []byte) error {
	if err := HMAC1(newHMAC, t0, key, input); err != nil {
		return err
	}
	return HMAC1(newHMAC, t0, t0, []byte{0x1})
}

func KDF2(newHMAC hmacFunc, t0, t1 []byte, key, input []byte) error {
	prk := make([]byte, len(t0))
	defer setZero(prk)

	if err := HMAC1(newHMAC, prk, key, input); err != nil {
		return err
	}
	if err := HMAC1(newHMAC, t0, prk, []byte{0x1}); err != nil {
		return err
	}
	return HMAC2(newHMAC, t1, prk, t0, []byte{0x2})
}

func KDF3(newHMAC hmacFunc, t0, t1, t2 []byte, key, input []byte) error {
	prk := make([]byte, len(t0))
	defer setZero(prk)

	if err := HMAC1(newHMAC, prk, key, input); err != nil {
		return err
	}
	if err := HMAC1(newHMAC, t0, prk, []byte{0x1}); err != nil {
		return err
	}
	if err := HMAC2(newHMAC, t1, prk, t0, []byte{0x2}); err != nil {
		return err
	}
	return HMAC2(newHMAC, t2, prk, t1, []byte{0x3})
}

func isZero(val []byte) bool {
	acc := byte(0)
	for _, b := range val {
		acc |= b
	}
	return acc == 0
}

/* This function is not used as pervasively as it should because this is mostly impossible in Go at the moment */
func setZero(arr []byte) {
	for i := range arr {
		arr[i] = 0
	}
}

/* The three key operations below delegate to the suite's key exchange rather
 * than calling wolfCrypt with a hardcoded curve. That is what lets a peer on a
 * different suite use a different key exchange; which implementation backs a
 * given name is decided by registration, not here.
 */

func newPrivateKey(kex suite.KEX) (sk NoisePrivateKey, err error) {
	if kex == nil {
		return sk, errNoSuite
	}
	priv, _, err := kex.GenerateKey()
	if err != nil {
		return sk, fmt.Errorf("generating a private key: %w", err)
	}
	if err := sk.SetBytes(priv); err != nil {
		return sk, err
	}
	return sk, nil
}

func (sk *NoisePrivateKey) publicKey(kex suite.KEX) (pk NoisePublicKey, err error) {
	if kex == nil {
		return pk, errNoSuite
	}
	pub, err := kex.PublicKey(sk.Bytes())
	if err != nil {
		return pk, fmt.Errorf("deriving a public key: %w", err)
	}
	if err := pk.SetBytes(pub); err != nil {
		return pk, err
	}
	return pk, nil
}

func (sk *NoisePrivateKey) sharedSecret(kex suite.KEX, pk NoisePublicKey) (ss []byte, err error) {
	if kex == nil {
		return nil, errNoSuite
	}
	ss, err = kex.SharedSecret(sk.Bytes(), pk.Bytes())
	if err != nil {
		return nil, fmt.Errorf("computing a shared secret: %w", err)
	}
	return ss, nil
}

var errInvalidPublicKey = errors.New("invalid public key")
