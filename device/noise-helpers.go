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

/* The KDFs below keep every value they chain on at the hash's own length and
 * copy only the leading bytes into the caller's buffers.
 *
 * That distinction is the whole of HKDF-Expand. The pseudorandom key and each
 * intermediate T(i) are one hash long; truncation happens where a value is
 * USED, never where it is fed back in as a key or appended as input. These
 * functions used to size the pseudorandom key from len(t0) and then chain on
 * the already-truncated T(1), which is the same thing only while the hash and
 * the output are the same width.
 *
 * Under SHA-256 they are: every output here is 32 bytes and so is the hash, so
 * nothing is truncated and the bytes are unchanged. Under SHA-384 they are not,
 * and BeginSymmetricSession asks for two 32-byte transport keys from a 48-byte
 * hash. Go and Rust completed a SHA-384 handshake and then passed no traffic
 * because of it, each agreeing with itself and with nothing else
 * (WOLFGUARD-AGILITY-6ytx.36).
 */

// hmacSum is HMAC(key, in...) at the hash's natural length.
func hmacSum(newHMAC hmacFunc, key []byte, ins ...[]byte) ([]byte, error) {
	h, err := newHMAC(key)
	if err != nil {
		return nil, fmt.Errorf("keying hmac: %w", err)
	}
	for _, in := range ins {
		if _, err := h.Write(in); err != nil {
			return nil, fmt.Errorf("hmac update: %w", err)
		}
	}
	return h.Sum(nil), nil
}

// fillLeading copies the leading len(dst) bytes of a full-length hmac output,
// which is what HKDF-Expand's "first L octets" means, and refuses a hash too
// short to supply them rather than returning a partly written key.
func fillLeading(dst, full []byte) error {
	if len(full) < len(dst) {
		return fmt.Errorf("hmac produced %d bytes, need %d: %w", len(full), len(dst), errKeySize)
	}
	copy(dst, full)
	return nil
}

func KDF1(newHMAC hmacFunc, t0 []byte, key, input []byte) error {
	prk, err := hmacSum(newHMAC, key, input)
	if err != nil {
		return err
	}
	defer setZero(prk)

	f0, err := hmacSum(newHMAC, prk, []byte{0x1})
	if err != nil {
		return err
	}
	defer setZero(f0)

	return fillLeading(t0, f0)
}

func KDF2(newHMAC hmacFunc, t0, t1 []byte, key, input []byte) error {
	prk, err := hmacSum(newHMAC, key, input)
	if err != nil {
		return err
	}
	defer setZero(prk)

	f0, err := hmacSum(newHMAC, prk, []byte{0x1})
	if err != nil {
		return err
	}
	defer setZero(f0)

	/* f0 whole, not t0: the next value chains on the full T(1). */
	f1, err := hmacSum(newHMAC, prk, f0, []byte{0x2})
	if err != nil {
		return err
	}
	defer setZero(f1)

	if err := fillLeading(t0, f0); err != nil {
		return err
	}
	return fillLeading(t1, f1)
}

func KDF3(newHMAC hmacFunc, t0, t1, t2 []byte, key, input []byte) error {
	prk, err := hmacSum(newHMAC, key, input)
	if err != nil {
		return err
	}
	defer setZero(prk)

	f0, err := hmacSum(newHMAC, prk, []byte{0x1})
	if err != nil {
		return err
	}
	defer setZero(f0)

	f1, err := hmacSum(newHMAC, prk, f0, []byte{0x2})
	if err != nil {
		return err
	}
	defer setZero(f1)

	f2, err := hmacSum(newHMAC, prk, f1, []byte{0x3})
	if err != nil {
		return err
	}
	defer setZero(f2)

	if err := fillLeading(t0, f0); err != nil {
		return err
	}
	if err := fillLeading(t1, f1); err != nil {
		return err
	}
	return fillLeading(t2, f2)
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
