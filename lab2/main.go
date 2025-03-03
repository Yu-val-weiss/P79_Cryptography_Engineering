package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"

	certauth "github.com/yu-val-weiss/p79_cryptography_engineering/lab2/cert_auth"
	"github.com/yu-val-weiss/p79_cryptography_engineering/lab2/sigma"
	"github.com/yu-val-weiss/p79_cryptography_engineering/lab2/spake2"
	"golang.org/x/crypto/curve25519"
)

var byte_a = []byte("A")
var byte_b = []byte("B")

func main() {
	const s_str = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
	const u_str = "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"
	s, s_err := hex.DecodeString(s_str)
	u, u_err := hex.DecodeString(u_str)
	if s_err != nil || u_err != nil {
		panic("error!")
	}
	b, err := curve25519.X25519(s, u)
	fmt.Printf("%v\n", hex.EncodeToString(b))
	fmt.Printf("%v\n", err)

	rand_s := make([]byte, 32)
	rand.Read(rand_s)
	b, err = curve25519.X25519(rand_s, u)
	fmt.Printf("%v\n", hex.EncodeToString(b))
	fmt.Printf("%v\n", err)

	c := slices.Concat(byte_a, byte_b)
	fmt.Printf("%v, %v, %v\n", hex.EncodeToString(byte_a), hex.EncodeToString(byte_b), hex.EncodeToString(c))
	hasher := sha256.New()
	hasher.Write(slices.Concat(byte_a, byte_b, []byte("testttttt"), []byte("testttttt"), []byte("testttttt"), []byte("testttttt")))

	fmt.Printf("%v\n", len(hasher.Sum(nil)))

	ca := certauth.NewAuthority()

	pub, _, _ := ed25519.GenerateKey(nil)
	ca.Register("Alice", pub)

	pubb, _, _ := ed25519.GenerateKey(nil)
	ca.Register("Bob", pubb)

	al_cert, _ := ca.Certify("Alice")

	fmt.Printf("%#v\n", al_cert)

	// fmt.Println(string(cert_data))

	fmt.Println(ca.VerifyCertificate(al_cert))

	// alice_cert := certauth.UnmarshalCertificate(cert_data)
	// fmt.Printf("%#v\n", ca)

	// fmt.Println(sig)
	_ = spake2.Client{}

	ca = certauth.NewAuthority()
	alice_reg := sigma.NewBaseClient("alice").Register(ca)
	bob_reg := sigma.NewBaseClient("bob").Register(ca)
	alice := alice_reg.AsInitiator()
	bob := bob_reg.AsChallenger()
	alice_session, bob_session, err := sigma.EstablishSecureChat(alice, bob)
	if err != nil {
		fmt.Printf("should not return an error, but returned %v\n", err)
	}
	msg := "Hey Bob!"
	fmt.Println("here!!")
	enc, err := alice_session.SendMessage(msg)
	if err != nil {
		fmt.Printf("sending a message should not error, but returned %v\n", err)
	}
	dec, err := bob_session.ReceiveMessage(enc)
	if err != nil {
		fmt.Printf("should not return an error. but got %v", err)
	}
	if dec.Content != msg {
		fmt.Printf("expected content to be %v, but got %v", msg, dec.Content)
	}
}
