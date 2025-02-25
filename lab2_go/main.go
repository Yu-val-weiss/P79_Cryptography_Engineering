package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"

	certauth "github.com/yu-val-weiss/p79_cryptography_engineering/lab2/cert_auth"
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

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	c_a := ca.RegisterCertificate("Alice", pub)

	v, _ := json.Marshal(c_a)
	fmt.Println(string(v))
}
