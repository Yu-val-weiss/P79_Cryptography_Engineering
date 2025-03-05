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
	rc, err := c.Register(ca)
	if err != nil {
		t.Errorf("expected client to register successfully, got error %v", err)
	}
	ca_cert_data, _ := ca.Certify("alice")
	ca_cert, _ := certauth.Unmarshal[certauth.ValidatedCertificate](ca_cert_data)
	if !bytes.Equal(rc.cert.PublicKey, ca_cert.Cert.PublicKey) {
		t.Errorf("expected certificates to be the same")
	}
}

func TestRegisterErrorsWithNilAuthority(t *testing.T) {
	if _, err := NewBaseClient("alice").Register(nil); err == nil {
		t.Errorf("expected error about nil certificate authority, got nil")
	}
}

func TestGetKeyFromNonCompletedState(t *testing.T) {
	_, err := getKeyFromCompletedState(challengerBegunState{})
	if err == nil {
		t.Error("expected error about wrong state, got nil")
	}
}
