package spake2

import (
	"crypto/sha256"
	"fmt"

	"filippo.io/edwards25519"
)

// initiate SPAKE-2 protocol
//
// source: lecture slides
func (c *Client) Initiate() ([]byte, error) {
	if _, ok := c.state.(*baseState); !ok {
		return nil, fmt.Errorf("client must be in base state before initiating SPAKE2")
	}
	x, err := makeScalar()
	if err != nil {
		return nil, fmt.Errorf("could not create scalar: error %v", err)
	}

	hasher := sha256.New()
	hasher.Write(c.password)
	w_bytes := hasher.Sum(nil)

	w, err := edwards25519.NewScalar().SetBytesWithClamping(w_bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to initiate SPAKE2: error %v", err)
	}

	g_x := &edwards25519.Point{}
	g_x.ScalarBaseMult(x)

	m_w := &edwards25519.Point{}
	m_w.ScalarMult(w, constM)

	pi_a := &edwards25519.Point{}
	pi_a.Add(g_x, m_w)

	c.state = &initiatedState{
		x:    x,
		w:    w,
		pi_a: pi_a,
	}

	return pi_a.Bytes(), nil
}

func (c *Client) Challenge() ([]byte, error) {
	if state, ok := c.state.(*initiatedState); !ok {
		return nil, fmt.Errorf("client must be in initiated state before returning a challenge post-initiation")
	}
}

func (c *Client) Finalise() ([]byte, error) {
	return nil, nil
}
