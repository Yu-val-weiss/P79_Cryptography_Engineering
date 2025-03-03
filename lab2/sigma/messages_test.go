package sigma

import "testing"

func TestUnmarshalChallengeError(t *testing.T) {
	if _, err := unmarshalChallenge([]byte("invalid")); err == nil {
		t.Errorf("expected error about impossible to unmarshal, got nil error")
	}
}

func TestUnmarshalResponseError(t *testing.T) {
	if _, err := unmarshalResponse([]byte("invalid")); err == nil {
		t.Errorf("expected error about impossible to unmarshal, got nil error")
	}
}
