// SPDX-FileCopyrightText: 2023 Thibault NORMAND <me@zenithar.org>
//
// SPDX-License-Identifier: Apache-2.0 AND MIT

// Package hpke provides RFC9180 hybrid public key encryption features.
package hpke

type mode uint8

const (
	modeBase    mode = 0x00
	modePsk     mode = 0x01
	modeAuth    mode = 0x02
	modeAuthPsk mode = 0x03
)
