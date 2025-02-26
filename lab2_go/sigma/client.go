package sigma

import (
	"crypto/ed25519"
	"fmt"

	certauth "github.com/yu-val-weiss/p79_cryptography_engineering/lab2/cert_auth"
)

// base client interface shared functionality
type BaseClient struct {
	Name    string
	Public  ed25519.PublicKey
	private ed25519.PrivateKey
}

type RegisteredClient struct {
	BaseClient
	ca *certauth.CertificateAuthority
}

// NewBaseClient creates a new instance of a BaseClient.
func NewBaseClient(name string) BaseClient {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(fmt.Sprintf("could not initialise client, error: %v", err))
	}
	return BaseClient{Name: name, Public: pub, private: priv}
}

// register a client with a certificate authority, ca must not be nil, will panic if so.
func (c BaseClient) Register(ca *certauth.CertificateAuthority) RegisteredClient {
	if ca == nil {
		panic("cannot register client to nil certificate authority")
	}
	ca.RegisterCertificate(c.Name, c.Public)
	return RegisteredClient{BaseClient: c, ca: ca}
}

func (c *RegisteredClient) GetCertificate() certauth.Certificate {
	cert, err := c.ca.GetCertificate(c.Name)
	if err != nil {
		panic("certificate not found with authority, client should have been registered")
	}
	return cert
}

// should only be called after the client has been registered with the required certificate authority
func (c *RegisteredClient) Certify() certauth.ValidatedCertificate {
	val_cert, err := c.ca.Certify(c.Name)
	if err != nil {
		panic("certificate not found with authority, client should have been registered")
	}
	return val_cert
}

// States (interfaces and subtypes)

// InitiatorState represents a state in the initiator's protocol flow
type InitiatorState interface {
	isInitiatorState() // A marker method to make the interface exclusive to initiator states
}

// ChallengerState represents a state in the challenger's protocol flow
type ChallengerState interface {
	isChallengerState() // A marker method to make the interface exclusive to challenger states
}

// Initiator client states

type InitiatorBaseState struct{}

func (s *InitiatorBaseState) isInitiatorState() {}

type InitiatorBegunState struct {
	x   []byte // private scalar used for public commitment g**x
	g_x []byte // public commitment g**x
}

func (s *InitiatorBegunState) isInitiatorState() {}

type ChallengerBaseState struct{}

func (s *ChallengerBaseState) isChallengerState() {}

type ChallengerBegunState struct {
	g_x []byte // public commitment
	g_y []byte // public challenge
	k_M []byte // MAC key
	k_S []byte // session key
}

func (s *ChallengerBegunState) isChallengerState() {}

// Shared completed state represents a client that has completed the protocol
type CompletedState struct {
	k_S []byte // session key
}

func (s *CompletedState) isInitiatorState() {}

func (s *CompletedState) isChallengerState() {}

// InitiatorClient represents the SIGMA protocol initiator (Alice)
type InitiatorClient struct {
	*RegisteredClient
	state InitiatorState
}

// AsInitiator converts a BaseClient to an InitiatorClient
func (c *RegisteredClient) AsInitiator() *InitiatorClient {
	return &InitiatorClient{
		RegisteredClient: c,
		state:            &InitiatorBaseState{},
	}
}

func getKeyFromState(state any) ([]byte, error) {
	s, ok := state.(*CompletedState)
	if !ok {
		return nil, fmt.Errorf("client is not in completed state")
	}
	return s.k_S, nil
}

// retrieves session key from an initiator client
func (c *InitiatorClient) SessionKey() ([]byte, error) {
	return getKeyFromState(c.state)
}

// retrieves session key from a challenger client
func (c *ChallengerClient) SessionKey() ([]byte, error) {
	return getKeyFromState(c.state)
}

// ChallengerClient represents the SIGMA protocol challenger (Bob)
type ChallengerClient struct {
	*RegisteredClient
	state ChallengerState
}

// AsChallenger creates a new instance of a ChallengerClient from a BaseClient.
func (c *RegisteredClient) AsChallenger(name string) *ChallengerClient {
	return &ChallengerClient{
		RegisteredClient: c,
		state:            &ChallengerBaseState{},
	}
}
