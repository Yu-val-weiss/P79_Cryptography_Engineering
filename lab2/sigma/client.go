package sigma

import (
	"crypto/ed25519"
	"fmt"
	"strings"

	certauth "github.com/yu-val-weiss/p79_cryptography_engineering/lab2/cert_auth"
)

// base client contains shared functionality
//
// hidden so cannot construct manually, only through [NewBaseClient]
// all fields are hidden to avoid manual user modification
type baseClient struct {
	name    string
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

// promotion baseClient registered to a [certauth.CertificateAuthority]
//
// hidden so cannot construct manually, only through promotion of [baseClient] with [baseClient.Register]
type registeredClient struct {
	*baseClient
	ca   certauth.CertificateAuthority
	cert certauth.Certificate
}

// Creates a new instance of a [*baseClient].
//
// Usage:
//
//	ca := certauth.NewCertificateAuthority()
//	alice := NewBaseClient("Alice")
//	alice.Register(ca)
//
// to initiate a SIGMA protocol instance, promote [registeredClient] using [registeredClient.AsInitiator]
//
//	alice_i := alice.AsInitiator()
//	alice_i.Initiate() // send this to another client
//	alice_i.Respond(received_data) // send returned value to other client, input received from other client
//	alice_i is now in finalised state, key can be retrieved with alice_i.SessionKey()
//
// to respond to an initiatation, assuming a [registeredClient] bob
//
//	bob_c := bob.AsChallenger()
//	bob_c.Challenge(initiation_data) // input received from initiating client, send result back
//	bob_c.Finalise(response_data) // response received from intiation client, nothing sent back
//	bob_c now in finalised state, key can be retrieved with bob_c.SessionKey()
func NewBaseClient(name string) *baseClient {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(fmt.Sprintf("could not initialise client due to key gen error: %v", err))
	}
	return &baseClient{name: name, public: pub, private: priv}
}

// return the name of the client
func (c *baseClient) Name() string {
	return strings.Clone(c.name) // defensive clone
}

// Register a client with a certificate authority, ca must not be nil, will panic if so.
//
// Returns [registeredClient], a promoted type that guarantees that the client is registered to the given [certauth.CertificateAuthority]
func (c *baseClient) Register(ca certauth.CertificateAuthority) (*registeredClient, error) {
	if ca == nil {
		panic("cannot register client to a nil certificate authority")
	}
	reg_req := certauth.MakeRegistrationRequest(c.name, c.public)
	cert_data, err := ca.Register(reg_req)
	if err != nil {
		return nil, fmt.Errorf("could not register client: %v", err)
	}
	cert, err := certauth.Unmarshal[certauth.Certificate](cert_data)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal certificate: %v", err)
	}
	return &registeredClient{
		baseClient: c,
		ca:         ca,
		cert:       cert,
	}, nil
}

// internal interface that allows for implementation of [CheckCAMatch]
type regclient interface {
	getCA() certauth.CertificateAuthority
}

// implement [regclient] interface for CheckCAMatch
//
// [initiatorClient] and [challengerClient] automatically implement this due to the struct embedding
func (c *registeredClient) getCA() certauth.CertificateAuthority {
	return c.ca
}

func CheckCAMatch[T1 regclient, T2 regclient](c1 T1, c2 T2) bool {
	return c1.getCA() == c2.getCA()
}

// convenience function for getting a [certauth.ValidatedCertificate] from the registered certificate authority
//
// should only be called after the client has been registered with the required certificate authority
func (c *registeredClient) Certify() (certauth.ValidatedCertificate, error) {
	data, err := c.ca.Certify(c.name)
	if err != nil {
		return certauth.ValidatedCertificate{}, err
	}
	return certauth.Unmarshal[certauth.ValidatedCertificate](data)
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

// base state for [initiatorClient], on initialisation with [registeredClient.AsInitiator]
type initiatorBaseState struct{}

func (s *initiatorBaseState) isInitiatorState() {}

// second, begun state for [initiatorClient], after [initiatorClient.Initiate] returns
//
// stores required secrets x and g_x
type initiatorBegunState struct {
	x   []byte // private scalar used for public commitment g**x
	g_x []byte // public commitment g**x
}

func (s *initiatorBegunState) isInitiatorState() {}

// base state for [challengerClient], on initialisation with [registeredClient.AsChallenger]
type challengerBaseState struct{}

func (s *challengerBaseState) isChallengerState() {}

// second, begun state for [challengerClient], after [challengerClient.Challenge] returns
//
// stores required secrets g_x, g_y, k_M, k_S
type challengerBegunState struct {
	g_x []byte // public commitment
	g_y []byte // public challenge
	k_M []byte // MAC key
	k_S []byte // session key
}

func (s *challengerBegunState) isChallengerState() {}

// completed state represents a client that has completed the protocol
//
// shared between [initiatorClient] and [challengerClient]
//
// [initiatorClient] enters this state after [initiatorClient.Respond] returns
//
// [challengerClient] enters this state after [challengerClient.Finalise] returns
type completedState struct {
	k_S []byte // session key
}

func (s *completedState) isInitiatorState() {}

func (s *completedState) isChallengerState() {}

type InitiatorClient = *initiatorClient

// initiatorClient represents the SIGMA protocol initiator (Alice)
type initiatorClient struct {
	*registeredClient
	state initiatorState
}

// AsInitiator promotes a [registeredClient] to an [initiatorClient]
func (c *registeredClient) AsInitiator() InitiatorClient {
	return &initiatorClient{
		registeredClient: c,
		state:            &initiatorBaseState{},
	}
}

// convenience function for getting the key from a [completedState] within a client
func getKeyFromCompletedState(state any) ([]byte, error) {
	s, ok := state.(*completedState)
	if !ok {
		return nil, fmt.Errorf("client is not in completed state")
	}
	return s.k_S, nil
}

// retrieves session key from an initiator client
// only returns if state is [completedState]
func (c *initiatorClient) SessionKey() ([]byte, error) {
	return getKeyFromCompletedState(c.state)
}

// challengerClient represents the SIGMA protocol challenger (Bob)
// hidden so cannot manually construct, can only create through [registeredClient.AsChallenger]
type challengerClient struct {
	*registeredClient
	state challengerState
}

type ChallengerClient = *challengerClient

// AsChallenger promotes a [registeredClient] to a [challengerClient]
func (c *registeredClient) AsChallenger() ChallengerClient {
	return &challengerClient{
		registeredClient: c,
		state:            &challengerBaseState{},
	}
}

// retrieves session key from a challenger client
// only returns if state is [completedState]
func (c *challengerClient) SessionKey() ([]byte, error) {
	return getKeyFromCompletedState(c.state)
}
