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

type Client struct {
	Name    string
	Public  ed25519.PublicKey
	private ed25519.PrivateKey
	x       []byte
	g_x     []byte
	k_M     []byte
	k_S     []byte
}

// New creates a new instance of a Client.
func NewClient(name string) Client {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("could not initialise client, error: %v", err))
	}
	return Client{Name: name, Public: pub, private: priv, k_M: nil, k_S: nil}
}

func (c *Client) Register(ca *certauth.CertificateAuthority) certauth.Certificate {
	return ca.RegisterCertificate(c.Name, c.Public)
}

func (c *Client) GetCertificate(ca *certauth.CertificateAuthority) certauth.Certificate {
	cert, err := ca.GetCertificate(c.Name)
	if err != nil {
		panic("certificate not found with authority, client should have been registered")
	}
	return cert
}

// should only be called after the client has been registered with the required certificate authority
func (c *Client) Certify(ca *certauth.CertificateAuthority) certauth.ValidatedCertificate {
	val_cert, err := ca.Certify(c.Name)
	if err != nil {
		panic("certificate not found with authority, client should have been registered")
	}
	return val_cert
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

// initiate as Alice, sends commitment g**x
func (a *Client) Initiate() []byte {
	x := makeScalar()
	res, err := curve25519.X25519(x, curve25519.Basepoint)
	if err != nil {
		panic(fmt.Sprintf("could not initiate SIGMA, error: %v", err))
	}
	a.x = x
	a.g_x = res
	return res
}

// challenge as Bob, data is g_x
// returns [ChallengeMsg] encoded as bytes
func (b *Client) Challenge(data []byte, ca *certauth.CertificateAuthority) []byte {
	y := makeScalar()

	g_y, err_1 := curve25519.X25519(y, data)
	g_xy, err_2 := curve25519.X25519(y, data)
	if err_1 != nil || err_2 != nil {
		panic("could not compute x25519 functions")
	}

	k_m, k_s := deriveKeys(g_xy)

	sig_b := ed25519.Sign(b.private, slices.Concat(data, g_y))

	c_b := b.Certify(ca)
	m_b := hMac(k_m, c_b.Cert.Marshal())

	// write k_m and k_s to client
	b.k_M = k_m
	b.k_S = k_s

	return ChallengeMsg{
		Challenge:   g_y,
		Certificate: c_b,
		Sig:         sig_b,
		Mac:         m_b,
	}.Marshal()
}

// respons as Alice, returns (k_s, marshalled message, error)
func (a *Client) Respond(data []byte, ca *certauth.CertificateAuthority) ([]byte, []byte, error) {
	challenge, err := UnmarshalChallenge(data)
	if err != nil {
		return nil, nil, fmt.Errorf("could not unmarshal challenge")
	}

	val_cert := challenge.Certificate

	if !ca.VerifyCertificate(val_cert) {
		return nil, nil, fmt.Errorf("could not verify certificate with CA")
	}

	g_yx, err_1 := curve25519.X25519(a.x, challenge.Challenge)
	if err_1 != nil {
		panic("could not compute x25519 function")
	}

	k_m, k_s := deriveKeys(g_yx)

	computed_m_b := hMac(k_m, val_cert.Cert.Marshal())

	if !bytes.Equal(computed_m_b, challenge.Mac) {
		return nil, nil, fmt.Errorf("could not validate challenge")
	}

	g_x_g_y := slices.Concat(a.g_x, challenge.Challenge)

	if !ed25519.Verify(val_cert.Cert.PublicKey, g_x_g_y, val_cert.Sig) {
		return nil, nil, fmt.Errorf("could not validate challenge")
	}

	sig_a := ed25519.Sign(a.private, g_x_g_y)

	c_a := a.Certify(ca)
	m_a := hMac(k_m, c_a.Cert.Marshal())

	return k_s, ResponseMsg{Certificate: c_a, Sig: sig_a, Mac: m_a}.Marshal(), nil
}

func (b *Client) Finalise(data []byte, ca *certauth.CertificateAuthority) ([]byte, error) {
	return nil, nil
}
