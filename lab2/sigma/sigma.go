package sigma

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"slices"

	"golang.org/x/crypto/curve25519"
)

// makeScalar generates a 32-byte scalar value.
func makeScalar() []byte {
	scalar := make([]byte, 32)
	if _, err := rand.Read(scalar); err != nil {
		panic("failed to generate random scalar")
	}
	return scalar
}

// performs the SHA256-based derivation of the MAC and session keys
func deriveKeys(base []byte) (k_m, k_s []byte) {
	hasher := sha256.New()
	hasher.Write(slices.Concat(base, []byte("MAC")))

	k_m = hasher.Sum(nil)

	hasher.Reset()
	hasher.Write(slices.Concat(base, []byte("session")))

	k_s = hasher.Sum(nil)
	return
}

// convenience function computing HMAC based on SHA256
func hMac(key []byte, data []byte) []byte {
	h_mac := hmac.New(sha256.New, key)
	h_mac.Write(data)
	return h_mac.Sum(nil)
}

// Initiate starts the SIGMA protocol and returns g^x
//
// State transitions:
//
//	[initatorBaseState] -> [initiatorBegunState]
//
// source: lecture slides
func (a *initiatorClient) Initiate() ([]byte, error) {
	if _, ok := a.state.(*initiatorBaseState); !ok {
		return nil, fmt.Errorf("client must be in base state before initiating")
	}
	x := makeScalar()
	g_x, err := curve25519.X25519(x, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("could not initiate SIGMA, error: %v", err)
	}
	a.state = &initiatorBegunState{
		x:   x,
		g_x: g_x,
	}
	return g_x, nil
}

// Challenge responds to an initiation with g^y and authentication data
//
// State transitions:
//
//	[challengerBaseState] -> [challengerBegunState]
//
// source: lecture slides
func (b *challengerClient) Challenge(data []byte) ([]byte, error) {
	if _, ok := b.state.(*challengerBaseState); !ok {
		return nil, fmt.Errorf("client must be in base state before challenging")
	}

	y := makeScalar()

	g_y, err := curve25519.X25519(y, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("could not compute x25519 function: %v", err)
	}

	g_xy, err := curve25519.X25519(y, data)
	if err != nil {
		return nil, fmt.Errorf("could not compute x25519 function: %v", err)
	}

	k_M, k_S := deriveKeys(g_xy)

	sig_b := ed25519.Sign(b.private, slices.Concat(data, g_y))

	c_b, err := b.Certify()
	if err != nil {
		return nil, fmt.Errorf("error certifiying client with authority: %v", err)
	}
	m_b := hMac(k_M, c_b.Cert.Marshal())

	b.state = &challengerBegunState{
		g_x: data,
		g_y: g_y,
		k_M: k_M,
		k_S: k_S,
	}

	msg := challengeMsg{
		Challenge:   g_y,
		Certificate: c_b,
		Sig:         sig_b,
		Mac:         m_b,
	}

	return msg.Marshal(), nil
}

// Respond handles the challenger's response and returns the response message and an error if it exists
//
// The session key is stored in the client, and can be retrieved with [initiatorClient.SessionKey]
//
// State transitions:
//
//	[initiatorBegunState] -> [completedState]
//
// source: lecture slides
func (a *initiatorClient) Respond(data []byte) ([]byte, error) {
	state, ok := a.state.(*initiatorBegunState)
	if !ok {
		return nil, fmt.Errorf("client must be in intermediate InitiatorBegunState to call this method, was in %T", a.state)
	}
	challenge, err := unmarshal[challengeMsg](data)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal challenge")
	}

	val_cert := challenge.Certificate

	if !a.ca.VerifyCertificate(val_cert.Marshal()) {
		return nil, fmt.Errorf("could not verify certificate with CA")
	}

	g_yx, err := curve25519.X25519(state.x, challenge.Challenge)
	if err != nil {
		return nil, fmt.Errorf("could not compute x25519 function: %v", err)
	}

	k_M, k_S := deriveKeys(g_yx)

	computed_m_b := hMac(k_M, val_cert.Cert.Marshal())

	if !bytes.Equal(computed_m_b, challenge.Mac) {
		return nil, fmt.Errorf("could not validate challenge")
	}

	g_x_g_y := slices.Concat(state.g_x, challenge.Challenge)

	if !ed25519.Verify(val_cert.Cert.PublicKey, g_x_g_y, challenge.Sig) {
		return nil, fmt.Errorf("could not validate challenge signature")
	}

	sig_a := ed25519.Sign(a.private, g_x_g_y)

	c_a, err := a.Certify()
	if err != nil {
		return nil, fmt.Errorf("error certifiying client with authority: %v", err)
	}
	m_a := hMac(k_M, c_a.Cert.Marshal())

	a.state = &completedState{k_S: k_S}

	return responseMsg{Certificate: c_a, Sig: sig_a, Mac: m_a}.Marshal(), nil
}

// Finalise verifies the initiator's response and returns an error if one has arisen (nil otherwise)
//
// The session key is stored in the client, and can be retrieved with [challengerClient.SessionKey]
//
// State transitions:
//
//	[challengerBegunState] -> [completedState]
//
// source: lecture slides
func (b *challengerClient) Finalise(data []byte) error {
	state, ok := b.state.(*challengerBegunState)
	if !ok {
		return fmt.Errorf("client not in intermediate ChallengerBegunState to call this method, was in %T", state)
	}

	response, err := unmarshal[responseMsg](data)
	if err != nil {
		return fmt.Errorf("could not unmarshal response data")
	}

	val_cert := response.Certificate

	if !b.ca.VerifyCertificate(val_cert.Marshal()) {
		return fmt.Errorf("could not verify certificate with CA")
	}

	if !bytes.Equal(hMac(state.k_M, val_cert.Cert.Marshal()), response.Mac) {
		return fmt.Errorf("could not validate MAC in response")
	}

	if !ed25519.Verify(val_cert.Cert.PublicKey, slices.Concat(state.g_x, state.g_y), response.Sig) {
		return fmt.Errorf("could not validate signature in response")
	}

	b.state = &completedState{k_S: state.k_S}

	return nil
}
