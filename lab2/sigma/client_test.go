package sigma

import (
	"bytes"
	"testing"

	certauth "github.com/yu-val-weiss/p79_cryptography_engineering/lab2/cert_auth"
)

func TestNewBaseClient(t *testing.T) {
	name := "alice"
	c := NewBaseClient(name)
	if c.Name != name {
		t.Errorf("expected name to be %v, was %v", name, c.Name)
	}
}

func TestRegisterClient(t *testing.T) {
	c := NewBaseClient("alice")
	ca := certauth.NewAuthority()
	rc := c.Register(ca)
	ca_cert, _ := ca.Certify("alice")
	if !bytes.Equal(rc.cert.PublicKey, ca_cert.Cert.PublicKey) {
		t.Errorf("expected certificates to be the same")
	}
}
