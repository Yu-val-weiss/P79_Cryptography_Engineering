package sigma

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"slices"

	certauth "github.com/yu-val-weiss/p79_cryptography_engineering/lab2/cert_auth"
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

func deriveKeys(base []byte) (k_m, k_s []byte) {
	hasher := sha256.New()
	hasher.Write(slices.Concat(base, []byte("MAC")))

	k_m = hasher.Sum(nil)

	hasher.Reset()
	hasher.Write(slices.Concat(base, []byte("session")))

	k_s = hasher.Sum(nil)
	return
}

func hMac(key []byte, data []byte) []byte {
	h_mac := hmac.New(sha256.New, key)
	h_mac.Write(data)
	return h_mac.Sum(nil)
}

// base client interface shared functionality
type baseClient struct {
	Name    string
	Public  ed25519.PublicKey
	private ed25519.PrivateKey
	ca      *certauth.CertificateAuthority
}

// newBaseClient creates a new instance of a BaseClient.
func newBaseClient(name string) baseClient {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("could not initialise client, error: %v", err))
	}
	return baseClient{Name: name, Public: pub, private: priv}
}

// register a client with a certificate authority, ca must not be nil, will panic if so.
func (c *baseClient) Register(ca *certauth.CertificateAuthority) certauth.Certificate {
	if ca == nil {
		panic("cannot register client to nil certificate authority")
	}
	c.ca = ca
	return ca.RegisterCertificate(c.Name, c.Public)
}

func (c *baseClient) checkCA() {
	if c.ca == nil {
		panic("client must be registered to a certification authority")
	}
}

func (c *baseClient) GetCertificate() certauth.Certificate {
	c.checkCA()
	cert, err := c.ca.GetCertificate(c.Name)
	if err != nil {
		panic("certificate not found with authority, client should have been registered")
	}
	return cert
}

// should only be called after the client has been registered with the required certificate authority
func (c *baseClient) Certify() certauth.ValidatedCertificate {
	c.checkCA()
	val_cert, err := c.ca.Certify(c.Name)
	if err != nil {
		panic("certificate not found with authority, client should have been registered")
	}
	return val_cert
}

// InitiatorClient represents the SIGMA protocol initiator (Alice)
type InitiatorClient struct {
	baseClient
	x   []byte // private scalar
	g_x []byte // public commitment
	g_y []byte // challenge received from responder
}

// NewInitiatorClient creates a new instance of an InitiatorClient.
func NewInitiatorClient(name string) InitiatorClient {
	return InitiatorClient{baseClient: newBaseClient(name)}
}

// ChallengerClient represents the SIGMA protocol challenger (Bob)
type ChallengerClient struct {
	baseClient
	g_x []byte // commitment received from initiator
	y   []byte // private scalar
	g_y []byte // public challenge
	k_M []byte // MAC key
	k_S []byte // session key
}

// NewChallengerClient creates a new instance of a ChallengerClient.
func NewChallengerClient(name string) ChallengerClient {
	return ChallengerClient{baseClient: newBaseClient(name)}
}

// Initiate starts the SIGMA protocol and returns g^x
func (a *InitiatorClient) Initiate() []byte {
	a.checkCA()

	x := makeScalar()
	res, err := curve25519.X25519(x, curve25519.Basepoint)
	if err != nil {
		panic(fmt.Sprintf("could not initiate SIGMA, error: %v", err))
	}
	a.x = x
	a.g_x = res
	return res
}

// Challenge responds to an initiation with g^y and authentication data
func (b *ChallengerClient) Challenge(data []byte) []byte {
	b.checkCA()

	y := makeScalar()
	b.y = y

	g_y, err_1 := curve25519.X25519(y, curve25519.Basepoint)
	g_xy, err_2 := curve25519.X25519(y, data)
	if err_1 != nil || err_2 != nil {
		panic("could not compute x25519 functions")
	}

	b.g_x = data
	b.g_y = g_y

	k_m, k_s := deriveKeys(g_xy)

	sig_b := ed25519.Sign(b.private, slices.Concat(data, g_y))

	c_b := b.Certify()
	m_b := hMac(k_m, c_b.Cert.Marshal())

	// store keys for later use
	b.k_M = k_m
	b.k_S = k_s

	return ChallengeMsg{
		Challenge:   g_y,
		Certificate: c_b,
		Sig:         sig_b,
		Mac:         m_b,
	}.Marshal()
}

// Respond handles the challenger's response and returns session key and response message
func (a *InitiatorClient) Respond(data []byte) ([]byte, []byte, error) {
	challenge, err := UnmarshalChallenge(data)
	if err != nil {
		return nil, nil, fmt.Errorf("could not unmarshal challenge")
	}

	val_cert := challenge.Certificate

	if !a.ca.VerifyCertificate(val_cert) {
		return nil, nil, fmt.Errorf("could not verify certificate with CA")
	}

	g_yx, err_1 := curve25519.X25519(a.x, challenge.Challenge)
	if err_1 != nil {
		panic("could not compute x25519 function")
	}

	a.g_y = challenge.Challenge

	k_m, k_s := deriveKeys(g_yx)

	computed_m_b := hMac(k_m, val_cert.Cert.Marshal())

	if !bytes.Equal(computed_m_b, challenge.Mac) {
		return nil, nil, fmt.Errorf("could not validate challenge")
	}

	g_x_g_y := slices.Concat(a.g_x, challenge.Challenge)

	if !ed25519.Verify(val_cert.Cert.PublicKey, g_x_g_y, challenge.Sig) {
		return nil, nil, fmt.Errorf("could not validate challenge signature")
	}

	sig_a := ed25519.Sign(a.private, g_x_g_y)

	c_a := a.Certify()
	m_a := hMac(k_m, c_a.Cert.Marshal())

	return k_s, ResponseMsg{Certificate: c_a, Sig: sig_a, Mac: m_a}.Marshal(), nil
}

// Finalise verifies the initiator's response and returns the session key
func (b *ChallengerClient) Finalise(data []byte) ([]byte, error) {
	response, err := UnmarshalResponse(data)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal response data")
	}

	val_cert := response.Certificate

	if !b.ca.VerifyCertificate(val_cert) {
		return nil, fmt.Errorf("could not verify certificate with CA")
	}

	if !bytes.Equal(hMac(b.k_M, val_cert.Cert.Marshal()), response.Mac) {
		return nil, fmt.Errorf("could not validate MAC in response")
	}

	if !ed25519.Verify(val_cert.Cert.PublicKey, slices.Concat(b.g_x, b.g_y), response.Sig) {
		return nil, fmt.Errorf("could not validate signature in response")
	}

	return b.k_S, nil
}
