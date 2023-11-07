// SPDX-FileCopyrightText: 2023 Thibault NORMAND <me@zenithar.org>
//
// SPDX-License-Identifier: Apache-2.0 AND MIT

package kdf

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"
)

// KDF describes iana-registered key derivation function.
// https://www.iana.org/assignments/hpke/hpke.xhtml
type KDF uint16

//nolint:stylecheck
const (
	// HKDF_SHA256 is a KDF using HKDF with SHA-256.
	HKDF_SHA256 KDF = 0x01
	// HKDF_SHA384 is a KDF using HKDF with SHA-384.
	HKDF_SHA384 KDF = 0x02
	// HKDF_SHA512 is a KDF using HKDF with SHA-512.
	HKDF_SHA512 KDF = 0x03
)

// IsValid checks if the given KDF is supported.
func (k KDF) IsValid() bool {
	switch k {
	case HKDF_SHA256, HKDF_SHA384, HKDF_SHA512:
		return true
	default:
		return false
	}
}

// ExtractSize returns the extracted buffer size.
func (k KDF) ExtractSize() uint16 {
	switch k {
	case HKDF_SHA256:
		return uint16(crypto.SHA256.Size())
	case HKDF_SHA384:
		return uint16(crypto.SHA384.Size())
	case HKDF_SHA512:
		return uint16(crypto.SHA512.Size())
	default:
		panic("invalid hash")
	}
}

// Extract a secret from given parameters.
func (k KDF) Extract(secret, salt []byte) []byte {
	return hkdf.Extract(k.hash(), secret, salt)
}

// Expand a pseudo random content to the expected length.
func (k KDF) Expand(prk, labeledInfo []byte, outputLen uint16) ([]byte, error) {
	extractSize := k.ExtractSize()
	// https://www.rfc-editor.org/rfc/rfc9180.html#kdf-input-length
	if len(prk) < int(extractSize) {
		return nil, fmt.Errorf("pseudorandom key must be at least %d bytes", extractSize)
	}
	// https://www.rfc-editor.org/rfc/rfc9180.html#name-secret-export
	if maxLength := 255 * extractSize; outputLen > maxLength {
		return nil, fmt.Errorf("expansion length is limited to %d", maxLength)
	}

	r := hkdf.Expand(k.hash(), prk, labeledInfo)
	out := make([]byte, outputLen)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("unable to generate value from kdf: %w", err)
	}

	return out, nil
}

func (k KDF) hash() func() hash.Hash {
	switch k {
	case HKDF_SHA256:
		return sha256.New
	case HKDF_SHA384:
		return sha512.New384
	case HKDF_SHA512:
		return sha512.New
	default:
		panic("invalid hash")
	}
}
