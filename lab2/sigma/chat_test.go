package sigma

import (
	"bytes"
	"fmt"
	"testing"

	certauth "github.com/yu-val-weiss/p79_cryptography_engineering/lab2/cert_auth"
)

func TestEstablishSecureChat(t *testing.T) {
	for i := range 50 {
		i := i // capture i locally
		t.Run(
			fmt.Sprintf("Run%v", i), func(t *testing.T) {
				t.Parallel()
				ca := certauth.NewAuthority()
				alice_reg := NewBaseClient("alice").Register(ca)
				bob_reg := NewBaseClient("bob").Register(ca)
				alice := alice_reg.AsInitiator()
				bob := bob_reg.AsChallenger()
				in_s, ch_s, err := EstablishSecureChat(alice, bob)
				if err != nil {
					t.Errorf("should not return an error, but returned %v", err)
				}
				if in_s.Local != "alice" && in_s.Remote != "bob" {
					t.Errorf("incorrect local and remote names, got %v and %v", in_s.Local, in_s.Remote)
				}
				if ch_s.Local != "bob" && ch_s.Remote != "alice" {
					t.Errorf("incorrect local and remote names, got %v and %v", ch_s.Local, ch_s.Remote)
				}
				if !bytes.Equal(in_s.SessionKey, ch_s.SessionKey) {
					t.Errorf("session keys should be equal, got:\n%v\n%v", in_s.SessionKey, ch_s.SessionKey)
				}

			},
		)
	}
}
