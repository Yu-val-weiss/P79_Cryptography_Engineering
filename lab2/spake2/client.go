package spake2

import (
	"fmt"

	"filippo.io/edwards25519"
)

type Client struct {
	password []byte
	state    clientState
}

func NewClient(password string) *Client {
	return &Client{
		password: []byte(password),
		state:    &baseState{},
	}
}

func (c *Client) Key() ([]byte, error) {
	state, ok := c.state.(*finalState)
	if !ok {
		return nil, fmt.Errorf("client not in final state, could not return key")
	}
	return state.k_e, nil
}

type clientState interface {
	isState() // marker method to show that a state is a [clientState]
}

type baseState struct{}

func (*baseState) isState() {} // implements [clientState] interface

type initiatedState struct {
	x    *edwards25519.Scalar
	w    *edwards25519.Scalar
	pi_a *edwards25519.Point
}

func (*initiatedState) isState() {} // implements [clientState] interface

type finalState struct {
	k_e []byte
}

func (*finalState) isState() {} // implements [clientState] interface
