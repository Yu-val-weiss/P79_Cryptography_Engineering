package spake2

import (
	"bytes"
	"fmt"
	"testing"
)

func TestSpakeSamePasswdGivesSameKey(t *testing.T) {
	for i := range 50 {
		i := i
		t.Run(fmt.Sprintf("SPAKE2 - Password: password%v", i), func(t *testing.T) {
			a := NewClient(fmt.Sprintf("password%v", i))
			b := NewClient(fmt.Sprintf("password%v", i))
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
		})
	}

}

func TestSpakeDiffPasswdReturnsErrs(t *testing.T) {
	a := NewClient("password1")
	b := NewClient("password2")
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
	if a.Validate(mu_b) == nil {
		t.Errorf("expected alice validation to fail")
	}
	if b.Validate(mu_a) == nil {
		t.Errorf("expected bob validation to fail")
	}
}

func TestInitiateErrorsIfInWrongState(t *testing.T) {
	a := NewClient("password1")
	a.state = &validatedState{}
	if _, err := a.initiate(false); err == nil {
		t.Errorf("expected error about wrong state, got nil")
	}
	if _, err := a.initiate(true); err == nil {
		t.Errorf("expected error about wrong state, got nil")
	}
}
func TestDeriveErrorsIfInWrongState(t *testing.T) {
	a := NewClient("password1")
	a.state = &validatedState{}
	if _, err := a.Derive([]byte("data")); err == nil {
		t.Errorf("expected error about wrong state, got nil")
	}
}

func TestValidateErrorsIfInWrongState(t *testing.T) {
	a := NewClient("password1")
	a.state = &validatedState{}
	if a.Validate([]byte("data")) == nil {
		t.Errorf("expected error about wrong state, got nil")
	}
}
