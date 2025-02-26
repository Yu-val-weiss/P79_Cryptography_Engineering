package sigma

import (
	"testing"

	certauth "github.com/yu-val-weiss/p79_cryptography_engineering/lab2/cert_auth"
)

func TestCannotCallFromIncorrectInitiatorState(t *testing.T) {
	ca := certauth.NewAuthority()
	alice_reg := NewBaseClient("alice").Register(ca)
	alice := alice_reg.AsInitiator()
	_, err := alice.Respond([]byte("invalid"))
	if err == nil {
		t.Errorf("expected error about incorrect state, got nil")
	} else {
		t.Logf("correctly got error: %v", err)
	}
	alice.state = &CompletedState{}
	_, err = alice.Initiate()
	if err == nil {
		t.Errorf("expected error about incorrect state, got nil")
	} else {
		t.Logf("correctly got error: %v", err)
	}
	_, err = alice.Respond([]byte("invalid"))
	if err == nil {
		t.Errorf("expected error about incorrect state, got nil")
	} else {
		t.Logf("correctly got error: %v", err)
	}
}

func TestCannotCallFromIncorrectChallengerState(t *testing.T) {
	ca := certauth.NewAuthority()
	bob_reg := NewBaseClient("bob").Register(ca)
	bob := bob_reg.AsChallenger()
	err := bob.Finalise([]byte("invalid"))
	if err == nil {
		t.Errorf("expected error about incorrect state, got nil")
	} else {
		t.Logf("correctly got error: %v", err)
	}
	bob.state = &CompletedState{}
	err = bob.Finalise([]byte("invalid"))
	if err == nil {
		t.Errorf("expected error about incorrect state, got nil")
	} else {
		t.Logf("correctly got error: %v", err)
	}
	_, err = bob.Challenge([]byte("invalid"))
	if err == nil {
		t.Errorf("expected error about incorrect state, got nil")
	} else {
		t.Logf("correctly got error: %v", err)
	}
}

func TestManualSigma(t *testing.T) {
	ca := certauth.NewAuthority()
	alice_reg := NewBaseClient("alice").Register(ca)
	bob_reg := NewBaseClient("bob").Register(ca)
	alice := alice_reg.AsInitiator()
	bob := bob_reg.AsChallenger()

	// begin SIGMA protocol
	g_x, err := alice.Initiate()
	if err != nil {
		t.Errorf("could not initiate secure chat session: %v", err)
	}

	switch alice.state.(type) {
	case *InitiatorBegunState:
		// pass
	default:
		t.Errorf("alice's state should be *InitiatorBegunState, got %T", alice.state)
	}

	// challenger responds
	challenge, err := bob.Challenge(g_x)
	if err != nil {
		t.Errorf("challenger failed, aborting session: %v", err)
	}

	switch bob.state.(type) {
	case *ChallengerBegunState:
		// pass
	default:
		t.Errorf("alice's state should be *ChallengerBegunState, got %T", bob.state)
	}

	// initiator responds again and derives its own session key
	resp, err := alice.Respond(challenge)
	if err != nil {
		t.Errorf("initiator response failed: %v", err)
	}

	switch alice.state.(type) {
	case *CompletedState:
		// pass
	default:
		t.Errorf("alice's state should be *CompletedState, got %T", alice.state)
	}

	// challenger finalises and gets session key
	err = bob.Finalise(resp)
	t.Logf("err: %v", err)
	if err != nil {
		t.Errorf("challenger finalisation failed: %v", err)
	}

	switch bob.state.(type) {
	case *CompletedState:
		// pass
	default:
		t.Errorf("alice's state should be *CompletedState, got %T", bob.state)
	}
}
