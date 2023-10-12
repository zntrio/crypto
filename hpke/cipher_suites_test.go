package hpke

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCipherSuites(t *testing.T) {
	t.Parallel()

	for id, c := range cipherSuites {
		id, c := id, c
		t.Run(c.Name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, c.Name, CipherSuiteName(id))
			
			msg := []byte("message")

			// Generate test keypair
			pkR, skR, err := c.Suite.KEM().GenerateKeyPair()
			require.NoError(t, err)

			// Prepare a sender
			enc, sealer, err := c.Suite.Sender(pkR, []byte("testing purpose")).SetupBase()
			require.NoError(t, err)

			// Seal the message
			ct1, err := sealer.Seal(msg, nil)
			require.NoError(t, err)
			ct2, err := sealer.Seal(msg, nil)
			require.NoError(t, err)
			require.NotEqual(t, ct1, ct2)

			// Prepare a receiver
			opener, err := c.Suite.Receiver(skR, []byte("testing purpose")).SetupBase(enc)
			require.NoError(t, err)

			pt1, err := opener.Open(ct1, nil)
			require.NoError(t, err)
			require.Equal(t, msg, pt1)
			pt2, err := opener.Open(ct2, nil)
			require.NoError(t, err)
			require.Equal(t, msg, pt2)
		})
	}
}