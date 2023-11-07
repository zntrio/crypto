package aead

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

// AEAD describes iana-registered AEAD cipher.
// https://www.iana.org/assignments/hpke/hpke.xhtml
type AEAD uint16

// https://www.iana.org/assignments/hpke/hpke.xhtml
//
//nolint:stylecheck
const (
	// AES128GCM is AES-128 block cipher in Galois Counter Mode (GCM).
	AES128GCM AEAD = 0x01
	// AES256GCM is AES-256 block cipher in Galois Counter Mode (GCM).
	AES256GCM AEAD = 0x02
	// ChaCha20Poly1305 is ChaCha20 stream cipher and Poly1305 MAC.
	ChaCha20Poly1305 AEAD = 0x03
	// EXPORT_ONLY is reserved for applications that only use the Exporter
	// interface.
	EXPORT_ONLY AEAD = 0xFFFF
)

// IsValid checks if the given AEAD is supported.
func (a AEAD) IsValid() bool {
	switch a {
	case AES128GCM, AES256GCM, ChaCha20Poly1305, EXPORT_ONLY:
		return true
	default:
		return false
	}
}

// New initializes an AEAD concrete AEAD cipher with the given key.
func (a AEAD) New(key []byte) (cipher.AEAD, error) {
	switch a {
	case AES128GCM, AES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case ChaCha20Poly1305:
		return chacha20poly1305.New(key)
	case EXPORT_ONLY:
		return nil, errors.New("AEAD cipher can't be initialized in export-only mode")
	default:
		panic("invalid aead")
	}
}

// KeySize returns the expected key size.
func (a AEAD) KeySize() uint16 {
	switch a {
	case AES128GCM:
		return 16
	case AES256GCM:
		return 32
	case ChaCha20Poly1305:
		return chacha20poly1305.KeySize
	case EXPORT_ONLY:
		return 0
	default:
		panic("invalid aead")
	}
}

// NonceSize returns the expected nonce size.
func (a AEAD) NonceSize() uint16 {
	switch a {
	case AES128GCM,
		AES256GCM,
		ChaCha20Poly1305:
		return 12
	case EXPORT_ONLY:
		return 0
	default:
		panic("invalid aead")
	}
}
