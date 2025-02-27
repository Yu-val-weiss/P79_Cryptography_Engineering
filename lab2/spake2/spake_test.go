package spake2

import (
	"bytes"
	"testing"
)

func TestSpakeSamePasswdGivesSameKey(t *testing.T) {
	a := NewClient("password")
	b := NewClient("password")
	pi_a, err := a.InitiateAsAlice()
	if err != nil {
		t.Errorf("alice initiation failed: %v", err)
	}
	pi_b, err := b.InitiateAsBob()
	if err != nil {
		t.Errorf("bob initiation failed: %v", err)
	}
	mu_a, err := a.Derive(pi_b)
	if err != nil {
		t.Errorf("alice derivation failed: %v", err)
	}
	mu_b, err := b.Derive(pi_a)
	if err != nil {
		t.Errorf("bob derivation failed: %v", err)
	}
	if err := a.Validate(mu_b); err != nil {
		t.Errorf("alice validation failed: %v", err)
	}
	if err := b.Validate(mu_a); err != nil {
		t.Errorf("bob validation failed: %v", err)
	}
	a_k, err := a.Key()
	if err != nil {
		t.Errorf("alice error getting key: %v", err)
	}
	b_k, err := b.Key()
	if err != nil {
		t.Errorf("alice error getting key: %v", err)
	}
	if !bytes.Equal(a_k, b_k) {
		t.Errorf("did not derive the same keys\nalice: %v\nbob: %v\n", a_k, b_k)
	}
}
