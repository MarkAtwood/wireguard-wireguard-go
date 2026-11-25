/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"errors"
	"fmt"
	wolfSSL "github.com/wolfssl/go-wolfssl"
	"golang.zx2c4.com/wireguard/suite"
)

/* KDF related functions.
 * HMAC-based Key Derivation Function (HKDF)
 * https://tools.ietf.org/html/rfc5869
 */

func HMAC1(sum []byte, key, in0 []byte) {
	hmac := wolfSSL.Wc_HmacAllocAligned()
	wolfSSL.Wc_HmacInit(hmac, nil, wolfSSL.INVALID_DEVID)
	wolfSSL.Wc_HmacSetKey(hmac, wolfSSL.WC_SHA256, key, len(key[:]))
	wolfSSL.Wc_HmacUpdate(hmac, in0, len(in0[:]))
	wolfSSL.Wc_HmacFinal(hmac, sum)
	wolfSSL.Wc_HmacFree(hmac)
	wolfSSL.Wc_HmacFreeAllocAligned(hmac)
}

func HMAC2(sum []byte, key, in0, in1 []byte) {
	hmac := wolfSSL.Wc_HmacAllocAligned()
	wolfSSL.Wc_HmacInit(hmac, nil, wolfSSL.INVALID_DEVID)
	wolfSSL.Wc_HmacSetKey(hmac, wolfSSL.WC_SHA256, key, len(key[:]))
	wolfSSL.Wc_HmacUpdate(hmac, in0, len(in0[:]))
	wolfSSL.Wc_HmacUpdate(hmac, in1, len(in1[:]))
	wolfSSL.Wc_HmacFinal(hmac, sum)
	wolfSSL.Wc_HmacFree(hmac)
	wolfSSL.Wc_HmacFreeAllocAligned(hmac)
}

func KDF1(t0 []byte, key, input []byte) {
	HMAC1(t0, key, input)
	HMAC1(t0, t0[:], []byte{0x1})
}

func KDF2(t0, t1 []byte, key, input []byte) {
	var prk [wolfSSL.WC_SHA256_DIGEST_SIZE]byte
	HMAC1(prk[:], key, input)
	HMAC1(t0, prk[:], []byte{0x1})
	HMAC2(t1, prk[:], t0[:], []byte{0x2})
	setZero(prk[:])
}

func KDF3(t0, t1, t2 []byte, key, input []byte) {
	var prk [wolfSSL.WC_SHA256_DIGEST_SIZE]byte
	HMAC1(prk[:], key, input)
	HMAC1(t0, prk[:], []byte{0x1})
	HMAC2(t1, prk[:], t0[:], []byte{0x2})
	HMAC2(t2, prk[:], t1[:], []byte{0x3})
	setZero(prk[:])
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
