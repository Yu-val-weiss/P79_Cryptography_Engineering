package spake2

import (
	"bytes"
	"slices"
	"testing"
)

func TestGetKey(t *testing.T) {
	client := NewClient("passwd")
	key := make([]byte, 32)
	for i := range 32 {
		key[i] = byte(i)
	}
	client.state = &validatedState{slices.Clone(key)}
	got_key, err := client.Key()
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
	if !bytes.Equal(key, got_key) {
		t.Errorf("expected key and got_key to be equal")
	}
}

func TestGetKeyErrorsInWrongState(t *testing.T) {
	client := NewClient("passwd")
	key := make([]byte, 32)
	for i := range 32 {
		key[i] = byte(i)
	}
	client.state = &derivedState{slices.Clone(key), slices.Clone(key), slices.Clone(key)}

	if _, err := client.Key(); err == nil {
		t.Errorf("expected error about wrong state, got nil")
	}
}
