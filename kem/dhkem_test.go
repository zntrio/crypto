// SPDX-FileCopyrightText: 2023 Thibault NORMAND <me@zenithar.org>
//
// SPDX-License-Identifier: Apache-2.0 AND MIT

package kem

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncapDecap(t *testing.T) {
	t.Parallel()

	suites := []Scheme{
		DHKEMP256HKDFSHA256(),
		DHKEMP384HKDFSHA384(),
		DHKEMP521HKDFSHA512(),
		DHKEMX25519HKDFSHA256(),
		DHKEMCP256HKDFSHA256(),
		DHKEMCP384HKDFSHA384(),
		DHKEMCP521HKDFSHA512(),
	}
	for _, suite := range suites {
		suite := suite
		t.Run("", func(t *testing.T) {
			t.Parallel()

			// Generate long term keys
			pk, sk, err := suite.GenerateKeyPair()
			require.NoError(t, err)

			ss1, enc, err := suite.Encapsulate(pk)
			require.NoError(t, err)

			ss2, err := suite.Decapsulate(enc, sk)
			require.NoError(t, err)
			require.Equal(t, ss1, ss2)
		})
	}
}

func TestAuthEncapAuthDecap(t *testing.T) {
	t.Parallel()

	suites := []Scheme{
		DHKEMP256HKDFSHA256(),
		DHKEMP384HKDFSHA384(),
		DHKEMP521HKDFSHA512(),
		DHKEMX25519HKDFSHA256(),
		DHKEMCP256HKDFSHA256(),
		DHKEMCP384HKDFSHA384(),
		DHKEMCP521HKDFSHA512(),
	}
	for _, suite := range suites {
		suite := suite
		t.Run("", func(t *testing.T) {
			t.Parallel()

			// Generate long term keys
			pkS, skS, err := suite.GenerateKeyPair()
			require.NoError(t, err)
			pkR, skR, err := suite.GenerateKeyPair()
			require.NoError(t, err)

			ss1, enc, err := suite.AuthEncapsulate(pkR, skS)
			require.NoError(t, err)

			ss2, err := suite.AuthDecapsulate(enc, skR, pkS)
			require.NoError(t, err)
			require.Equal(t, ss1, ss2)
		})
	}
}
