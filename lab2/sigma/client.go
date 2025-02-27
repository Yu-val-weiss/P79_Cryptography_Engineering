package sigma

import (
	"crypto/ed25519"
	"fmt"
	"slices"

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
	ca   *certauth.CertificateAuthority
	cert certauth.Certificate
}

// NewBaseClient creates a new instance of a BaseClient.
func NewBaseClient(name string) BaseClient {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(fmt.Sprintf("could not initialise client, due to key gen error: %v", err))
	}
	return BaseClient{Name: name, Public: pub, private: priv}
}

// Register a client with a certificate authority, ca must not be nil, will panic if so.
//
// Returns [RegisteredClient], a promoted type that guarantees that the client is registered to the given [certauth.CertificateAuthority]
func (c BaseClient) Register(ca *certauth.CertificateAuthority) RegisteredClient {
	if ca == nil {
		panic("cannot register client to a nil certificate authority")
	}
	cert := ca.Register(c.Name, c.Public)
	return RegisteredClient{
		BaseClient: BaseClient{
			Name:    c.Name,
			Public:  slices.Clone(c.Public),  // defensive clone
			private: slices.Clone(c.private), // defensive clone
		},
		ca:   ca,
		cert: cert,
	}
}

// should only be called after the client has been registered with the required certificate authority
func (c *RegisteredClient) Certify() certauth.ValidatedCertificate {
	val_cert, err := c.ca.Certify(c.Name)
	if err != nil {
		panic(fmt.Sprintf("could not certify client due to error: %v", err))
	}
	return val_cert
}

// States (interfaces and subtypes)

// initiatorState represents a state in the initiator's protocol flow
type initiatorState interface {
	isInitiatorState() // A marker method to make the interface exclusive to initiator states
}

// challengerState represents a state in the challenger's protocol flow
type challengerState interface {
	isChallengerState() // A marker method to make the interface exclusive to challenger states
}

// Initiator client states

type initiatorBaseState struct{}

func (s *initiatorBaseState) isInitiatorState() {}

type initiatorBegunState struct {
	x   []byte // private scalar used for public commitment g**x
	g_x []byte // public commitment g**x
}

func (s *initiatorBegunState) isInitiatorState() {}

type challengerBaseState struct{}

func (s *challengerBaseState) isChallengerState() {}

type challengerBegunState struct {
	g_x []byte // public commitment
	g_y []byte // public challenge
	k_M []byte // MAC key
	k_S []byte // session key
}

func (s *challengerBegunState) isChallengerState() {}

// completed state represents a client that has completed the protocol, in either the initiator or challenger role
type completedState struct {
	k_S []byte // session key
}

func (s *completedState) isInitiatorState() {}

func (s *completedState) isChallengerState() {}

// InitiatorClient represents the SIGMA protocol initiator (Alice)
type InitiatorClient struct {
	*RegisteredClient
	state initiatorState
}

// AsInitiator converts a BaseClient to an InitiatorClient
func (c *RegisteredClient) AsInitiator() *InitiatorClient {
	return &InitiatorClient{
		RegisteredClient: c,
		state:            &initiatorBaseState{},
	}
}

func getKeyFromCompletedState(state any) ([]byte, error) {
	s, ok := state.(*completedState)
	if !ok {
		return nil, fmt.Errorf("client is not in completed state")
	}
	return s.k_S, nil
}

// retrieves session key from an initiator client
// only returns if state is [completedState]
func (c *InitiatorClient) SessionKey() ([]byte, error) {
	return getKeyFromCompletedState(c.state)
}

// ChallengerClient represents the SIGMA protocol challenger (Bob)
type ChallengerClient struct {
	*RegisteredClient
	state challengerState
}

// AsChallenger creates a new instance of a ChallengerClient from a BaseClient.
func (c *RegisteredClient) AsChallenger() *ChallengerClient {
	return &ChallengerClient{
		RegisteredClient: c,
		state:            &challengerBaseState{},
	}
}

// retrieves session key from a challenger client
// only returns if state is [completedState]
func (c *ChallengerClient) SessionKey() ([]byte, error) {
	return getKeyFromCompletedState(c.state)
}
