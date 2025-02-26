package certauth

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestNewAuthority(t *testing.T) {
	ca := NewAuthority()
	if len(ca.regcerts) != 0 {
		t.Errorf("registered certificates is not empty")
	}
}

func TestRegisterCertificate(t *testing.T) {
	ca := NewAuthority()
	ca.Register("Alice", make(ed25519.PublicKey, 32))
	ca.Register("Bob", make(ed25519.PublicKey, 32))
	if l := len(ca.regcerts); l != 2 {
		t.Errorf("expected 2 certificates, got %v", l)
	}
}

func TestCannotModifyRegisteredCertificate(t *testing.T) {
	ca := NewAuthority()
	p_k := make(ed25519.PublicKey, 32)
	ca.Register("Alice", p_k)
	p_k[0] = byte(255)
	if bytes.Equal(p_k, ca.regcerts["Alice"].PublicKey) {
		t.Errorf("should not be able to modify public key externally")
	}
}

func TestMarshalUnmarshalCertificate(t *testing.T) {
	before := NewCertificate("Alice", make(ed25519.PublicKey, 32))
	data := before.Marshal()
	after, _ := UnmarshalCertificate(data)
	if before.Name != after.Name {
		t.Errorf("name: before %v should match %v", before.Name, after.Name)
	}
	if !before.Start.Equal(after.Start) {
		t.Errorf("start: %v should match %v", before.Start, after.Start)
	}
	if !before.End.Equal(after.End) {
		t.Errorf("end: %v should match %v", before.End, after.End)
	}
	if !bytes.Equal(before.PublicKey, after.PublicKey) {
		t.Errorf("pk: before %#v should be the same as after %#v", before.PublicKey, after.PublicKey)
	}
}

func TestCertifyVerifyWorks(t *testing.T) {
	ca := NewAuthority()
	pub, _, _ := ed25519.GenerateKey(nil)
	ca.Register("Alice", pub)
	val_cert, _ := ca.Certify("Alice")
	if !ca.VerifyCertificate(val_cert) {
		t.Error("certificate should be valid")
	}
}
