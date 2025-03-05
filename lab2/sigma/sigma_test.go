package sigma

import (
	"slices"
	"testing"

	certauth "github.com/yu-val-weiss/p79_cryptography_engineering/lab2/cert_auth"
)

func TestCannotCallFromIncorrectInitiatorState(t *testing.T) {
	ca := certauth.NewAuthority()
	alice_reg, err := NewBaseClient("alice").Register(ca)
	if err != nil {
		t.Errorf("expected alice registration to succeed, got error %v", err)
	}
	alice := alice_reg.AsInitiator()
	if _, err := alice.Respond([]byte("invalid")); err == nil {
		t.Errorf("expected error about incorrect state, got nil")
	} else {
		t.Logf("correctly got error: %v", err)
	}
	alice.state = &completedState{}
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
	bob_reg, err := NewBaseClient("bob").Register(ca)
	if err != nil {
		t.Errorf("expected alice registration to succeed, got error %v", err)
	}
	bob := bob_reg.AsChallenger()
	if err := bob.Finalise([]byte("invalid")); err == nil {
		t.Errorf("expected error about incorrect state, got nil")
	} else {
		t.Logf("correctly got error: %v", err)
	}
	bob.state = &completedState{}
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

	// begin SIGMA protocol
	g_x, err := alice.Initiate()
	if err != nil {
		t.Errorf("could not initiate secure chat session: %v", err)
	}

	switch alice.state.(type) {
	case *initiatorBegunState:
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
	case *challengerBegunState:
		// pass
	default:
		t.Errorf("bob's state should be *ChallengerBegunState, got %T", bob.state)
	}

	// initiator responds again and derives its own session key
	resp, err := alice.Respond(challenge)
	if err != nil {
		t.Errorf("initiator response failed: %v", err)
	}

	switch alice.state.(type) {
	case *completedState:
		// pass
	default:
		t.Errorf("alice's state should be *CompletedState, got %T", alice.state)
	}

	// challenger finalises and gets session key
	err = bob.Finalise(resp)
	if err != nil {
		t.Errorf("challenger finalisation failed: %v", err)
	}

	switch bob.state.(type) {
	case *completedState:
		// pass
	default:
		t.Errorf("alice's state should be *CompletedState, got %T", bob.state)
	}
}

func TestSigmaErrors(t *testing.T) {

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

	// begin SIGMA protocol
	g_x, err := alice.Initiate()
	if err != nil {
		t.Errorf("could not initiate secure chat session: %v", err)
	}

	switch alice.state.(type) {
	case *initiatorBegunState:
		// pass
	default:
		t.Errorf("alice's state should be *InitiatorBegunState, got %T", alice.state)
	}

	// change authority to prevent certification, this could not actually happen
	bob.registeredClient.ca = certauth.NewAuthority()

	// challenger responds

	if _, err := bob.Challenge(g_x); err == nil {
		t.Errorf("expected challenge to fail due to certauth error")
	}

	bob.registeredClient.ca = ca

	challenge, _ := bob.Challenge(g_x)

	switch bob.state.(type) {
	case *challengerBegunState:
		// pass
	default:
		t.Errorf("bob's state should be *sigma., got %T", bob.state)
	}

	// initiator responds again and derives its own session key
	// do it with invalid challenge response
	if _, err := alice.Respond([]byte("invalid")); err == nil {
		t.Error("expected error about unmarshalling challenge")
	}

	alice.ca = certauth.NewAuthority()
	if _, err := alice.Respond(challenge); err == nil {
		t.Error("expected error about certificate authority")
	}
	alice.ca = ca

	chall_msg, _ := unmarshalChallenge(challenge)
	mac := slices.Clone(chall_msg.Mac)
	chall_msg.Mac[1] -= 1
	chall_msg.Mac[2] -= 2

	if _, err := alice.Respond(chall_msg.Marshal()); err == nil {
		t.Errorf("expected error about MAC, got nil")
	}

	chall_msg.Mac = mac

	sig := slices.Clone(chall_msg.Sig)
	chall_msg.Sig[0] -= 1
	chall_msg.Sig[1] -= 2

	if _, err := alice.Respond(chall_msg.Marshal()); err == nil {
		t.Errorf("expected error about signature, got nil")
	}

	chall_msg.Sig = sig

	resp, err := alice.Respond(challenge)
	if err != nil {
		t.Errorf("initiator response failed: %v", err)
	}

	switch alice.state.(type) {
	case *completedState:
		// pass
	default:
		t.Errorf("alice's state should be *CompletedState, got %T", alice.state)
	}

	// challenger finalises and gets session key

	if err := bob.Finalise([]byte("invalid")); err == nil {
		t.Errorf("expected error about decoding data, got nil")
	}

	bob.ca = certauth.NewAuthority()
	if bob.Finalise(resp) == nil {
		t.Errorf("expected error about verifying certificate")
	}

	resp_msg, err := unmarshal[responseMsg](resp)
	if err != nil {
		t.Errorf("did not expect error unmarshalling, got %v", err)
	}
	bob.ca = ca

	// mess Mac
	mac = slices.Clone(resp_msg.Mac)
	resp_msg.Mac[0] -= 1
	resp_msg.Mac[1] -= 2

	if bob.Finalise(resp_msg.Marshal()) == nil {
		t.Errorf("expected error about mac, got nil")
	}

	resp_msg.Mac = mac

	sig = slices.Clone(resp_msg.Sig)
	resp_msg.Sig[0] -= 1
	resp_msg.Sig[1] -= 2

	if bob.Finalise(resp_msg.Marshal()) == nil {
		t.Errorf("expected error about sig, got nil")
	}

	resp_msg.Sig = sig

	err = bob.Finalise(resp)
	if err != nil {
		t.Errorf("challenger finalisation failed: %v", err)
	}

	switch bob.state.(type) {
	case *completedState:
		// pass
	default:
		t.Errorf("bob's state should be *CompletedState, got %T", bob.state)
	}
}
