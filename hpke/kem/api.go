// SPDX-FileCopyrightText: 2023 Thibault NORMAND <me@zenithar.org>
//
// SPDX-License-Identifier: Apache-2.0 AND MIT

package kem

import (
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/sha512"
)

// Scheme defines the default KEM suite contract.
type Scheme interface {
	SuiteID() []byte
	GenerateKeyPair() (*ecdh.PublicKey, *ecdh.PrivateKey, error)
	DeriveKeyPair(seed []byte) (*ecdh.PublicKey, *ecdh.PrivateKey, error)
	SerializePublicKey(pkX *ecdh.PublicKey) []byte
	DeserializePublicKey(pkXxm []byte) (*ecdh.PublicKey, error)
	SerializePrivateKey(sk *ecdh.PrivateKey) []byte
	DeserializePrivateKey(skRaw []byte) (*ecdh.PrivateKey, error)
	Encapsulate(pkR *ecdh.PublicKey) (ss, enc []byte, err error)
	EncapsulateDeterministically(seed []byte, pkR *ecdh.PublicKey) (ss, enc []byte, err error)
	Decapsulate(enc []byte, skR *ecdh.PrivateKey) ([]byte, error)
	AuthEncapsulate(pkR *ecdh.PublicKey, skS *ecdh.PrivateKey) (ss, enc []byte, err error)
	AuthEncapsulateDeterministically(seed []byte, pkR *ecdh.PublicKey, skS *ecdh.PrivateKey) (ss, enc []byte, err error)
	AuthDecapsulate(enc []byte, skR *ecdh.PrivateKey, pkS *ecdh.PublicKey) ([]byte, error)
	EncapsulationSize() uint16
	PublicKeySize() uint16
	PrivateKeySize() uint16
	SecretSize() uint16
}

// KEM represent iana-registered KEM identifier.
// https://www.iana.org/assignments/hpke/hpke.xhtml
type KEM uint16

//nolint:stylecheck
const (
	DHKEM_P256_HDKF_SHA256   KEM = 0x0010
	DHKEM_P384_HDKF_SHA384   KEM = 0x0011
	DHKEM_P521_HDKF_SHA512   KEM = 0x0012
	DHKEM_CP256_HDKF_SHA256  KEM = 0x0013
	DHKEM_CP384_HDKF_SHA384  KEM = 0x0014
	DHKEM_CP521_HDKF_SHA512  KEM = 0x0015
	DHKEM_X25519_HDKF_SHA256 KEM = 0x0020
)

// Scheme returns an initialized KEM scheme instance.
func (k KEM) Scheme() Scheme {
	switch k {
	case DHKEM_P256_HDKF_SHA256:
		return DHKEMP256HKDFSHA256()
	case DHKEM_P384_HDKF_SHA384:
		return DHKEMP384HKDFSHA384()
	case DHKEM_P521_HDKF_SHA512:
		return DHKEMP521HKDFSHA512()
	case DHKEM_CP256_HDKF_SHA256:
		return DHKEMCP256HKDFSHA256()
	case DHKEM_CP384_HDKF_SHA384:
		return DHKEMCP384HKDFSHA384()
	case DHKEM_CP521_HDKF_SHA512:
		return DHKEMCP521HKDFSHA512()
	case DHKEM_X25519_HDKF_SHA256:
		return DHKEMX25519HKDFSHA256()
	default:
		panic("invalid kem suite")
	}
}

// IsValid checks if the given KEM is supported.
func (k KEM) IsValid() bool {
	switch k {
	case DHKEM_P256_HDKF_SHA256, DHKEM_P384_HDKF_SHA384, DHKEM_P521_HDKF_SHA512,
		DHKEM_CP256_HDKF_SHA256, DHKEM_CP384_HDKF_SHA384, DHKEM_CP521_HDKF_SHA512,
		DHKEM_X25519_HDKF_SHA256:
		return true
	default:
		return false
	}
}

// DHKEMP256HKDFSHA256 defines a KEM Suite based on P-256 curve with HKDF-SHA256
// for shared secret derivation.
func DHKEMP256HKDFSHA256() Scheme {
	return &dhkem{
		kemID:          DHKEM_P256_HDKF_SHA256,
		curve:          ecdh.P256(),
		fh:             sha256.New,
		nSecret:        32,
		nEnc:           65,
		nPk:            65,
		nSk:            32,
		keyDeriverFunc: ecDeriver(ecdh.P256()),
	}
}

// DHKEMP384HKDFSHA384 defines a KEM Suite based on P-384 curve with HKDF-SHA384
// for shared secret derivation.
func DHKEMP384HKDFSHA384() Scheme {
	return &dhkem{
		kemID:          DHKEM_P384_HDKF_SHA384,
		curve:          ecdh.P384(),
		fh:             sha512.New384,
		nSecret:        48,
		nEnc:           97,
		nPk:            97,
		nSk:            48,
		keyDeriverFunc: ecDeriver(ecdh.P384()),
	}
}

// DHKEMP521HKDFSHA512 defines a KEM Suite based on P-521 curve with HKDF-SHA512
// for shared secret derivation.
func DHKEMP521HKDFSHA512() Scheme {
	return &dhkem{
		kemID:          DHKEM_P521_HDKF_SHA512,
		curve:          ecdh.P521(),
		fh:             sha512.New,
		nSecret:        64,
		nEnc:           133,
		nPk:            133,
		nSk:            66,
		keyDeriverFunc: ecDeriver(ecdh.P521()),
	}
}

// DHKEMX25519HKDFSHA256 defines a KEM Suite based on Curve25519 curve with
// HKDF-SHA256 for shared secret derivation.
func DHKEMX25519HKDFSHA256() Scheme {
	return &dhkem{
		kemID:          DHKEM_X25519_HDKF_SHA256,
		curve:          ecdh.X25519(),
		fh:             sha256.New,
		nSecret:        32,
		nEnc:           32,
		nPk:            32,
		nSk:            32,
		keyDeriverFunc: xDeriver,
	}
}

// DHKEMCP256HKDFSHA256 defines a KEM Suite based on compact P-256 curve with
// HKDF-SHA256 for shared secret derivation.
func DHKEMCP256HKDFSHA256() Scheme {
	return &dhkem{
		kemID:          DHKEM_CP256_HDKF_SHA256,
		curve:          ecdh.P256(),
		fh:             sha256.New,
		nSecret:        32,
		nEnc:           32,
		nPk:            32,
		nSk:            32,
		keyDeriverFunc: ecDeriver(ecdh.P256()),
		useCompact:     true,
	}
}

// DHKEMCP384HKDFSHA384 defines a KEM Suite based on compact P-384 curve with
// HKDF-SHA384 for shared secret derivation.
func DHKEMCP384HKDFSHA384() Scheme {
	return &dhkem{
		kemID:          DHKEM_CP384_HDKF_SHA384,
		curve:          ecdh.P384(),
		fh:             sha512.New384,
		nSecret:        48,
		nEnc:           48,
		nPk:            48,
		nSk:            48,
		keyDeriverFunc: ecDeriver(ecdh.P384()),
		useCompact:     true,
	}
}

// DHKEMCP521HKDFSHA512 defines a KEM Suite based on compact P-521 curve with
// HKDF-SHA512 for shared secret derivation.
func DHKEMCP521HKDFSHA512() Scheme {
	return &dhkem{
		kemID:          DHKEM_CP521_HDKF_SHA512,
		curve:          ecdh.P521(),
		fh:             sha512.New,
		nSecret:        64,
		nEnc:           66,
		nPk:            66,
		nSk:            66,
		keyDeriverFunc: ecDeriver(ecdh.P521()),
		useCompact:     true,
	}
}
