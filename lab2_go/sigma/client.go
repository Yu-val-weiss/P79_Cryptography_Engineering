package sigma

import (
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

type Client struct {
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

// New creates a new instance of Alice.
func NewClient() *Client {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("could not initialise client, error: %v", err))
	}
	return &Client{public: pub, private: priv}
}

// initiate as Alice
func (a *Client) Initiate() []byte {
	x := makeScalar()
	res, err := curve25519.X25519(x, curve25519.Basepoint)
	if err != nil {
		panic(fmt.Sprintf("could not initiate SIGMA, error: %v", err))
	}
	return res
}

// respond as Bob, data is g_x
func (b *Client) Respond(data []byte) {
	y := makeScalar()

	g_y, err_1 := curve25519.X25519(y, data)
	g_xy, err_2 := curve25519.X25519(y, data)
	if err_1 != nil || err_2 != nil {
		panic("could not compute")
	}

	hasher := sha256.New()
	hasher.Write(slices.Concat(g_xy, []byte("MAC")))

	k_m := hasher.Sum(nil)

	hasher.Reset()
	hasher.Write(slices.Concat(g_xy, []byte("session")))

	k_s := hasher.Sum(nil)

	sig_b := ed25519.Sign(b.private, slices.Concat(data, g_y))


	h_mac := hmac.New(sha256.New(), b.private)
	c_b := // get from certificate authority
	m_b := 

}
