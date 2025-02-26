package sigma

import (
	"encoding/json"
	"fmt"

	certauth "github.com/yu-val-weiss/p79_cryptography_engineering/lab2/cert_auth"
)

// struct defining response type (Bob -> Alice) for SIGMA protocol
type ChallengeMsg struct {
	Challenge   []byte                        `json:"challenge"` // Bob's challenge g**y to Alice's commitment g**x
	Certificate certauth.ValidatedCertificate `json:"cert"`      // Bob's validated certificate c_b
	Sig         []byte                        `json:"sig"`       // Bob's signature σ_b
	Mac         []byte                        `json:"mac"`       // Bob's HMAC µ_b
}

func (r ChallengeMsg) Marshal() []byte {
	data, err := json.Marshal(r)
	if err != nil {
		panic("could not marshal commitment message") // should never happen
	}
	return data
}

func UnmarshalChallenge(data []byte) (ChallengeMsg, error) {
	var chall ChallengeMsg
	if err := json.Unmarshal(data, &chall); err != nil {
		return chall, fmt.Errorf("could not unmarshall JSON, error: %v", err)
	}
	return chall, nil
}

type ResponseMsg struct {
	Certificate certauth.ValidatedCertificate `json:"cert"` // Alice's validated certificate c_a
	Sig         []byte                        `json:"sig"`  // Alice's signature σ_a
	Mac         []byte                        `json:"mac"`  // Alice's HMAC µ_a
}

func (r ResponseMsg) Marshal() []byte {
	data, err := json.Marshal(r)
	if err != nil {
		panic("could not marshal response message") // should never happen
	}
	return data
}

func UnmarshalResponse(data []byte) (ResponseMsg, error) {
	var resp ResponseMsg
	if err := json.Unmarshal(data, &resp); err != nil {
		return resp, fmt.Errorf("could not unmarshall JSON, error: %v", err)
	}
	return resp, nil
}
