package spake2

import (
	"fmt"

	"filippo.io/edwards25519"
)

// SPAKE2 client
type Client = *client

// internal SPAKE2 client struct
//
// unexported so can only create using [NewClient]
type client struct {
	password []byte
	state    clientState
}

// Creates a new SPAKE2 client from a given string password
//
// Example code, ignoring error handling
//
//	a, b := NewClient("password"), NewClient("password")
//	pi_a, _ := a.InitiateAsAlice()
//	pi_b, _ := b.InitiateAsBob()
//	mu_a, _ := a.Derive(pi_b)
//	mu_b, _ := b.Derive(pi_a)
//	err_a := a.Validate(mu_b)
//	err_b := b.Validate(mu_a)
//	a_k, _ := a.Key() // works if err_a is nil
//	b_k, _ := b.Key() // works if err_b is nil
//
// Proper error handling is achieved by checking that the returned error is nil at each stage
func NewClient(password string) Client {
	return &client{
		password: []byte(password),
		state:    &baseState{},
	}
}

// retrieve shared key upon completion of SPAKE2 protcol, from final state
func (c *client) Key() ([]byte, error) {
	state, ok := c.state.(*validatedState)
	if !ok {
		return nil, fmt.Errorf("client not in final state, could not return key")
	}
	return state.k_e, nil
}

// interface for client states
type clientState interface {
	isState() // marker method to show that a state is a [clientState]
}

// base state, when client is initialised
type baseState struct{}

func (*baseState) isState() {} // marker method for implementing [clientState] interface

// when client has begun the protocol
type initiatedState struct {
	secret *edwards25519.Scalar // secret scalar chosen randomly
	w      *edwards25519.Scalar
	pi     *edwards25519.Point
	alice  bool // boolean flag, if the client is in the role of "Alice" in this exchange
}

func (*initiatedState) isState() {} // marker method for implementing [clientState] interface

// post key derivation state, just waiting on last message to validate
type derivedState struct {
	k_cX []byte
	t    []byte
	k_e  []byte
}

func (*derivedState) isState() {} // marker method for implementing [clientState] interface

// validation has occured, protocol is complete, key is stored
type validatedState struct {
	k_e []byte
}

func (*validatedState) isState() {} // marker method for implementing [clientState] interface
