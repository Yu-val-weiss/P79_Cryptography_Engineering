package sigma

import (
	"bytes"
	"fmt"
	"regexp"
	"testing"

	certauth "github.com/yu-val-weiss/p79_cryptography_engineering/lab2/cert_auth"
)

func TestMessageToString(t *testing.T) {
	m := NewMessage("Alice", "Bob", "Hi Bob!")
	re := regexp.MustCompile(`\[.+\] Alice -> Bob: Hi Bob!`)
	if !re.MatchString(m.String()) {
		t.Errorf("message should match regex, got %v", m)
	}
}

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

func TestMessageSending(t *testing.T) {
	for i := range 50 {
		i := i
		t.Run(fmt.Sprintf("SendMessage%v", i), func(t *testing.T) {
			t.Parallel()
			ca := certauth.NewAuthority()
			alice_reg := NewBaseClient("alice").Register(ca)
			bob_reg := NewBaseClient("bob").Register(ca)
			alice := alice_reg.AsInitiator()
			bob := bob_reg.AsChallenger()
			alice_session, bob_session, err := EstablishSecureChat(alice, bob)
			if err != nil {
				t.Errorf("should not return an error, but returned %v", err)
			}
			msg := fmt.Sprintf("Hey Bob! Number %v", i)
			enc, err := alice_session.SendMessage(msg)
			if err != nil {
				t.Errorf("sending a message should not error, but returned %v", err)
			}
			dec, err := bob_session.ReceiveMessage(enc)
			if err != nil {
				t.Errorf("should not return an error. but got %v", err)
			}
			if dec.Content != msg {
				t.Errorf("expected content to be %v, but got %v", msg, dec.Content)
			}
			msg = fmt.Sprintf("Hey Alice, nice to chat! Number %v", i)
			enc, err = bob_session.SendMessage(msg)
			if err != nil {
				t.Errorf("sending a message should not error, but returned %v", err)
			}
			dec, err = alice_session.ReceiveMessage(enc)
			if err != nil {
				t.Errorf("should not return an error. but got %v", err)
			}
			if dec.Content != msg {
				t.Errorf("expected content to be %v, but got %v", msg, dec.Content)
			}
		})
	}
}

func TestDecryptInvalidMessage(t *testing.T) {
	cs := chatSession{"l", "s", make([]byte, 32)}
	_, err := cs.decrypt([]byte("invalid"))
	if err == nil {
		t.Errorf("expected decoding error")
	}
}

func TestEstablishSecureChatErrors(t *testing.T) {
	ca := certauth.NewAuthority()
	ca_2 := certauth.NewAuthority()
	alice_reg := NewBaseClient("alice").Register(ca)
	// bob_reg := NewBaseClient("bob").Register(ca)
	bob_reg_2 := NewBaseClient("bob").Register(ca_2)
	alice := alice_reg.AsInitiator()
	// bob := bob_reg.AsChallenger()
	bob_2 := bob_reg_2.AsChallenger()
	_, _, err := EstablishSecureChat(alice, bob_2)
	if err == nil {
		t.Errorf("should return an error about incompatible certificate authorities, but returned nil")
	}
}
