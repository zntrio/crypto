package hpke

import (
	"fmt"

	"zntr.io/crypto/hpke/aead"
	"zntr.io/crypto/hpke/kdf"
	"zntr.io/crypto/hpke/kem"
)

func Example() {
	// Prepare HPKE suite.
	s := New(kem.DHKEM_X25519_HDKF_SHA256, kdf.HKDF_SHA256, aead.ChaCha20Poly1305)

	// Generate a remote public key matching the key group.
	pkR, skR, err := s.KEM().GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	// -------------------------------------------------------------------------

	// Prepare a message sealer.
	enc, sealer, err := s.Sender(pkR, []byte("sample test purpose")).SetupBase()
	if err != nil {
		panic(err)
	}

	// Seal a plaintext content.
	ct, err := sealer.Seal([]byte("my message to secure"), nil)
	if err != nil {
		panic(err)
	}

	// -------------------------------------------------------------------------

	// Prepare the message opener.
	opener, err := s.Receiver(skR, []byte("sample test purpose")).SetupBase(enc)
	if err != nil {
		panic(err)
	}

	// Open a sealed content.
	pt, err := opener.Open(ct, nil)
	if err != nil {
		panic(err)
	}

	// Bidirectional encryption
	// https://www.rfc-editor.org/rfc/rfc9180.html#name-bidirectional-encryption

	responseKeyR, err := opener.Export([]byte("response key"), aead.ChaCha20Poly1305.KeySize())
	if err != nil {
		panic(err)
	}
	responseNonceR, err := opener.Export([]byte("response nonce"), aead.ChaCha20Poly1305.NonceSize())
	if err != nil {
		panic(err)
	}

	responseCipherR, err := s.AEAD().New(responseKeyR)
	if err != nil {
		panic(err)
	}

	response := responseCipherR.Seal(nil, responseNonceR, pt, enc)

	// -------------------------------------------------------------------------

	responseKeyS, err := sealer.Export([]byte("response key"), aead.ChaCha20Poly1305.KeySize())
	if err != nil {
		panic(err)
	}
	responseNonceS, err := sealer.Export([]byte("response nonce"), aead.ChaCha20Poly1305.NonceSize())
	if err != nil {
		panic(err)
	}

	responseCipherS, err := s.AEAD().New(responseKeyS)
	if err != nil {
		panic(err)
	}

	got, err := responseCipherS.Open(response[:0], responseNonceS, response, enc)
	if err != nil {
		panic(err)
	}

	// Output: my message to secure
	fmt.Printf("%s", string(got))
}
