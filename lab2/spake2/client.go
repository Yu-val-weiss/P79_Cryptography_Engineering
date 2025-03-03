package spake2

import (
	"fmt"

	"filippo.io/edwards25519"
)

// SPAKE2 client struct
//
// unexported so can only create using [NewClient]
type client struct {
	password []byte
	state    clientState
}

// creates a new SPAKE2 client given a password
func NewClient(password string) *client {
	return &client{
		password: []byte(password),
		state:    &baseState{},
	}
}

// Retrieve shared key following SPAKE2 protcol, from final state
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

// validation has occured, now has the key
type validatedState struct {
	k_e []byte
}

func (*validatedState) isState() {} // marker method for implementing [clientState] interface
