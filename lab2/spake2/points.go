package spake2

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"filippo.io/edwards25519"
)

const m_hex string = "d048032c6ea0b6d697ddc2e86bda85a33adac920f1bf18e1b0c6d166a5cecdaf"
const n_hex string = "d3bfb518f44f3430f29d0c92af503865a1ed3281dc69b35dd868ba85f886c4ab"

var constM *edwards25519.Point // canonical M point for SPAKE2 protocol, MUST NOT MODIFY
var constN *edwards25519.Point // canonical N point for SPAKE2 protocol, MUST NOT MODIFY

func init() {
	constM, constN = &edwards25519.Point{}, &edwards25519.Point{}
	m_data, err := hex.DecodeString(m_hex)
	if err != nil {
		panic(fmt.Sprintf("error decoding m_hex: %v", err))
	}
	n_data, err := hex.DecodeString(n_hex)
	if err != nil {
		panic(fmt.Sprintf("error decoding n_hex: %v", err))
	}
	_, err = constM.SetBytes(m_data)
	if err != nil {
		panic(fmt.Sprintf("error initialising point M: %v", err))
	}
	_, err = constN.SetBytes(n_data)
	if err != nil {
		panic(fmt.Sprintf("error initialising point N: %v", err))
	}
}

// makeScalar generates a 32-byte [edwards25519.Scalar] value.
func makeScalar() (*edwards25519.Scalar, error) {
	scalar_bytes := make([]byte, 32)
	if _, err := rand.Read(scalar_bytes); err != nil {
		panic(fmt.Sprintf("failed to generate random scalar, err: %v", err))
	}
	scalar, err := edwards25519.NewScalar().SetBytesWithClamping(scalar_bytes)
	if err != nil {
		panic(fmt.Sprintf("failed to generate random scalar, err: %v", err))
	}
	return scalar, nil
}
