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
	for i := range 1_000 {
		i := i // capture i locally
		t.Run(
			fmt.Sprintf("Run%v", i), func(t *testing.T) {
				t.Parallel()
				ca := certauth.NewAuthority()
				alice_reg, err := NewBaseClient("alice").Register(ca)
				if err != nil {
					t.Errorf("expected alice registration to succeed, got error %v", err)
				}
				bob_reg, err := NewBaseClient("bob").Register(ca)
				if err != nil {
					t.Errorf("expected bob registration to succeed, got error %v", err)
				}
				alice := alice_reg.AsInitiator()
				bob := bob_reg.AsChallenger()
				in_s, ch_s, err := EstablishSecureChat(alice, bob)
				if err != nil {
					t.Errorf("should not return an error, but returned %v", err)
				}
				if in_s.local != "alice" && in_s.remote != "bob" {
					t.Errorf("incorrect local and remote names, got %v and %v", in_s.local, in_s.remote)
				}
				if ch_s.local != "bob" && ch_s.remote != "alice" {
					t.Errorf("incorrect local and remote names, got %v and %v", ch_s.local, ch_s.remote)
				}
				if !bytes.Equal(in_s.sessionKey, ch_s.sessionKey) {
					t.Errorf("session keys should be equal, got:\n%v\n%v", in_s.sessionKey, ch_s.sessionKey)
				}

			},
		)
	}
}

func TestMessageSending(t *testing.T) {
	for i := range 1_000 {
		i := i
		t.Run(fmt.Sprintf("SendMessage%v", i), func(t *testing.T) {
			t.Parallel()
			ca := certauth.NewAuthority()
			alice_reg, err := NewBaseClient("alice").Register(ca)
			if err != nil {
				t.Errorf("expected alice registration to succeed, got error %v", err)
			}
			bob_reg, err := NewBaseClient("bob").Register(ca)
			if err != nil {
				t.Errorf("expected bob registration to succeed, got error %v", err)
			}
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
	alice_reg, err := NewBaseClient("alice").Register(ca)
	if err != nil {
		t.Errorf("expected alice registration to succeed, got error %v", err)
	}
	bob_reg, err := NewBaseClient("bob").Register(ca_2)
	if err != nil {
		t.Errorf("expected bob registration to succeed, got error %v", err)
	}
	alice := alice_reg.AsInitiator()
	bob := bob_reg.AsChallenger()
	if _, _, err := EstablishSecureChat(alice, bob); err == nil {
		t.Errorf("should return an error about incompatible certificate authorities, but returned nil")
	}
}
