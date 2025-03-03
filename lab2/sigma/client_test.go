package sigma

import (
	"bytes"
	"testing"

	certauth "github.com/yu-val-weiss/p79_cryptography_engineering/lab2/cert_auth"
)

func TestNewBaseClient(t *testing.T) {
	name := "alice"
	c := NewBaseClient(name)
	if c.name != name {
		t.Errorf("expected name to be %v, was %v", name, c.name)
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

func TestRegisterPanicsWithNilAuthority(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic, but did not")
		}
	}()
	c := NewBaseClient("alice")
	c.Register(nil)
}

func TestGetKeyFromNonCompletedState(t *testing.T) {
	_, err := getKeyFromCompletedState(challengerBegunState{})
	if err == nil {
		t.Error("expected error about wrong state, got nil")
	}
}
