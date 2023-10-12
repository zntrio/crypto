// SPDX-FileCopyrightText: 2023 Thibault NORMAND <me@zenithar.org>
//
// SPDX-License-Identifier: Apache-2.0 AND MIT

package hpke

import "fmt"

// CipherSuite object is used to map a name to a pre-built suite.
type CipherSuite struct {
	Name string
	Suite Suite
}

//nolint:stylecheck
const (
	HPKE_V1_P256_SHA256_AES128GCM uint16 = 0x0001
	HPKE_V1_P256_SHA256_CHACHA20POLY1305 uint16 = 0x0002
	HPKE_V1_P256_SHA256_AES256GCM uint16 = 0x0003
	HPKE_V1_P384_SHA384_AES128GCM uint16 = 0x0004
	HPKE_V1_P384_SHA384_CHACHA20POLY1305 uint16 = 0x0005
	HPKE_V1_P384_SHA384_AES256GCM uint16 = 0x0006
	HPKE_V1_P521_SHA512_AES256GCM uint16 = 0x0007
	HPKE_V1_P521_SHA512_CHACHA20POLY1305 uint16 = 0x0008
	HPKE_V1_X25519_SHA256_CHACHA20POLY1305 uint16 = 0x0009
)

var (
	cipherSuites = map[uint16]*CipherSuite{
		HPKE_V1_P256_SHA256_AES128GCM: {
			Name: "HPKE-V1 DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM",
			Suite: New(KEM_P256_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES128GCM),
		},
		HPKE_V1_P256_SHA256_CHACHA20POLY1305: {
			Name: "HPKE-V1 DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, Chacha20-Poly1305",
			Suite: New(KEM_P256_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_ChaCha20Poly1305),
		},
		HPKE_V1_P256_SHA256_AES256GCM: {
			Name: "HPKE-V1 DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM",
			Suite: New(KEM_P256_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES256GCM),
		},
		HPKE_V1_P384_SHA384_AES128GCM: {
			Name: "HPKE-V1 DHKEM(P-384, HKDF-SHA384), HKDF-SHA384, AES-128-GCM",
			Suite: New(KEM_P384_HKDF_SHA384, KDF_HKDF_SHA384, AEAD_AES128GCM),
		},
		HPKE_V1_P384_SHA384_CHACHA20POLY1305: {
			Name: "HPKE-V1 DHKEM(P-384, HKDF-SHA384), HKDF-SHA384, Chacha20-Poly1305",
			Suite: New(KEM_P384_HKDF_SHA384, KDF_HKDF_SHA384, AEAD_ChaCha20Poly1305),
		},
		HPKE_V1_P384_SHA384_AES256GCM: {
			Name: "HPKE-V1 DHKEM(P-384, HKDF-SHA384), HKDF-SHA384, AES-256-GCM",
			Suite: New(KEM_P384_HKDF_SHA384, KDF_HKDF_SHA384, AEAD_AES256GCM),
		},
		HPKE_V1_P521_SHA512_AES256GCM: {
			Name: "HPKE-V1 DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM",
			Suite: New(KEM_P521_HKDF_SHA512, KDF_HKDF_SHA512, AEAD_AES256GCM),
		},
		HPKE_V1_P521_SHA512_CHACHA20POLY1305: {
			Name: "HPKE-V1 DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, Chacha20-Poly1305",
			Suite: New(KEM_P521_HKDF_SHA512, KDF_HKDF_SHA512, AEAD_ChaCha20Poly1305),
		},
		HPKE_V1_X25519_SHA256_CHACHA20POLY1305: {
			Name: "HPKE-V1 DHKEM(Curve25519, HKDF-SHA256), HKDF-SHA256, Chacha20-Poly1305",
			Suite: New(KEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_ChaCha20Poly1305),
		},
	}
)

// CipherSuiteName lookup and find the ciphersuite name, returns the hexadecimal
// identifier if not found.
func CipherSuiteName(id uint16) string {
	if c, ok := cipherSuites[id]; ok {
		return c.Name
	}
	
	return fmt.Sprintf("0x%04X", id)
}