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

func TestReRegisterWithSamePK(t *testing.T) {
	ca := NewAuthority()
	p_k := make(ed25519.PublicKey, 32)
	c_1 := ca.Register("Alice", p_k)
	c_2 := ca.Register("Alice", p_k)

	if l := len(ca.regcerts); l != 1 {
		t.Errorf("expected 1 certificates, got %v", l)
	}

	if !c_1.End.Equal(c_2.End) {
		t.Errorf("certificate validity should have stayed the same")
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

func TestInvalidUnmarhsalGivesError(t *testing.T) {
	if _, err := UnmarshalCertificate([]byte("invalid certificate data")); err == nil {
		t.Errorf("expected error for unmarshalling an invalid certificate")
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

func TestCertifyWithoutRegistering(t *testing.T) {
	ca := NewAuthority()
	if _, err := ca.Certify("alice"); err == nil {
		t.Errorf("expected error about unregistered certificate")
	}
}

func TestExpiredCertificate(t *testing.T) {
	ca := NewAuthority()
	cert := ca.Register("Alice", make(ed25519.PublicKey, 32))
	ca.regcerts["Alice"] = Certificate{
		Name:      cert.Name,
		Start:     cert.Start.AddDate(-1, 0, 0),
		End:       cert.End.AddDate(-1, 0, 0),
		PublicKey: cert.PublicKey,
	}
	_, err := ca.Certify("Alice")
	if err == nil {
		t.Errorf("expected error about out of data certificate")
	}
}

func TestVerifyCertificateFails(t *testing.T) {
	ca := NewAuthority()
	ca.Register("Alice", make(ed25519.PublicKey, 32))
	val_cert, err := ca.Certify("Alice")
	if err != nil {
		t.Errorf("expected nill error, got %v", err)
	}
	messed_cert := val_cert.Cert.Clone()
	messed_cert.Name = "Alicia"
	inval_cert := ValidatedCertificate{messed_cert, val_cert.Sig}
	if ca.VerifyCertificate(inval_cert) {
		t.Errorf("expected to return false, since certificate did not match signature")
	}
	expired_cert := val_cert.Cert.Clone()
	expired_cert.Start = expired_cert.Start.AddDate(0, -5, 0)
	expired_cert.End = expired_cert.End.AddDate(0, -5, 0)
}
