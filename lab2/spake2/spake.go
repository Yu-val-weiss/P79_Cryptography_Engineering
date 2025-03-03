package spake2

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"slices"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/hkdf"
)

// Initiate SPAKE2 protocol, returns pi and an error if one arose
//
// The boolean argument alice indicates which variant of the formulae to use.
// This is hidden and the public methods which should be used are [client.InitiateAsAlice] and [client.InitiateAsBob]
//
// source: lecture slides
func (c *client) initiate(alice bool) ([]byte, error) {
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

	mn_w := &edwards25519.Point{}

	if alice {
		mn_w.ScalarMult(w, constM)
	} else {
		mn_w.ScalarMult(w, constN)
	}

	pi := &edwards25519.Point{}
	pi.Add(g_x, mn_w)

	c.state = &initiatedState{
		secret: x,
		w:      w,
		pi:     pi,
		alice:  alice,
	}

	return pi.Bytes(), nil
}

// Initiate SPAKE2 protocol in the role of Alice, returns pi_a and an error if one arose
func (c *client) InitiateAsAlice() ([]byte, error) {
	return c.initiate(true)
}

// Initiate SPAKE2 protocol in the role of Bob, returns pi_b and an error if one arose
func (c *client) InitiateAsBob() ([]byte, error) {
	return c.initiate(false)
}

// Second stage of protocol
//
// data is the [edwards25519.Point] encoded as []byte returned from opposing client's [client.Initiate]
//
// source: lecture slides
func (c *client) Derive(data []byte) ([]byte, error) {
	state, ok := c.state.(*initiatedState)
	if !ok {
		return nil, fmt.Errorf("client must be in initiated state before returning a challenge")
	}
	pi_in := &edwards25519.Point{}
	_, err := pi_in.SetBytes(data)
	if err != nil {
		return nil, fmt.Errorf("could not decode input data, error: %v", err)
	}

	neg_w := edwards25519.NewScalar().Negate(state.w)
	mn_w := &edwards25519.Point{}
	if state.alice {
		mn_w.ScalarMult(neg_w, constN)
	} else {
		mn_w.ScalarMult(neg_w, constM)
	}
	mn_w.Add(pi_in, mn_w)

	h_sec := edwards25519.NewScalar().Multiply(constH, state.secret)

	K := &edwards25519.Point{}
	K.ScalarMult(h_sec, mn_w)

	var pi_a_pi_b []byte
	if state.alice {
		pi_a_pi_b = slices.Concat(state.pi.Bytes(), data)
	} else {
		pi_a_pi_b = slices.Concat(data, state.pi.Bytes())
	}

	T := slices.Concat([]byte("A"), []byte("B"), pi_a_pi_b, K.Bytes(), state.w.Bytes())

	hasher := sha256.New()
	hasher.Write(T)
	hash_bytes := hasher.Sum(nil)
	K_e, K_a := hash_bytes[:16], hash_bytes[16:]

	hkdf := hkdf.New(sha256.New, K_a, nil, nil)
	key_bytes := make([]byte, 32)
	if _, err = io.ReadFull(hkdf, K_a); err != nil {
		return nil, fmt.Errorf("could not derive keys, error: %v", err)
	}
	K_cA, K_cB := key_bytes[:16], key_bytes[16:]

	var h_mac hash.Hash
	if state.alice {
		h_mac = hmac.New(sha256.New, K_cA)
	} else {
		h_mac = hmac.New(sha256.New, K_cB)
	}

	h_mac.Write(T)
	mu := h_mac.Sum(nil)

	var k_cX []byte

	if state.alice {
		k_cX = K_cB
	} else {
		k_cX = K_cA
	}

	c.state = &derivedState{
		k_cX: k_cX,
		t:    T,
		k_e:  K_e,
	}

	return mu, nil
}

// Final stage of protocol
// Data is mu_x receive from other side
//
// If nil is returned, then K_e is stored in the client state and can be retrieved with [client.Key]
//
// source: lecture slides
func (c *client) Validate(data []byte) error {
	state, ok := c.state.(*derivedState)
	if !ok {
		return fmt.Errorf("client must be in challenge state before finalising")
	}
	hmac := hmac.New(sha256.New, state.k_cX)
	hmac.Write(state.t)
	mu := hmac.Sum(nil)
	if !bytes.Equal(data, mu) {
		return fmt.Errorf("could not finalise SPAKE2: data does not match")
	}
	c.state = &validatedState{
		k_e: state.k_e,
	}
	return nil
}
