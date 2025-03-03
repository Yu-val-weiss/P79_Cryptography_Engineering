package spake2

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"filippo.io/edwards25519"
)

// constants sourced from RFC
var constM *edwards25519.Point  // canonical M point for SPAKE2 protocol, MUST NOT MODIFY
var constN *edwards25519.Point  // canonical N point for SPAKE2 protocol, MUST NOT MODIFY
var constH *edwards25519.Scalar // cofactor H encoded as a scalar for SPAKE2 protocol, MUST NOT MODIFY

func init() {
	const m_hex string = "d048032c6ea0b6d697ddc2e86bda85a33adac920f1bf18e1b0c6d166a5cecdaf"
	const n_hex string = "d3bfb518f44f3430f29d0c92af503865a1ed3281dc69b35dd868ba85f886c4ab"
	const cofactor uint64 = 8

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
	h_bytes := make([]byte, 32)
	binary.LittleEndian.PutUint64(h_bytes, cofactor)
	constH, err = edwards25519.NewScalar().SetCanonicalBytes(h_bytes)
	if err != nil {
		panic(fmt.Sprintf("error initialising scalar h: %v", err))
	}
}
