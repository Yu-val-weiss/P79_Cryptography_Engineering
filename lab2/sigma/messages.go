package sigma

import (
	"encoding/json"
	"fmt"

	certauth "github.com/yu-val-weiss/p79_cryptography_engineering/lab2/cert_auth"
)

// internal struct defining challenge message (Bob -> Alice) for SIGMA protocol
type challengeMsg struct {
	Challenge   []byte                        `json:"challenge"` // Bob's challenge g**y to Alice's commitment g**x
	Certificate certauth.ValidatedCertificate `json:"cert"`      // Bob's validated certificate c_b
	Sig         []byte                        `json:"sig"`       // Bob's signature σ_b
	Mac         []byte                        `json:"mac"`       // Bob's HMAC µ_b
}

func (r challengeMsg) marshal() []byte {
	data, err := json.Marshal(r)
	if err != nil {
		panic("could not marshal commitment message") // should never happen
	}
	return data
}

func unmarshalChallenge(data []byte) (challengeMsg, error) {
	var chall challengeMsg
	if err := json.Unmarshal(data, &chall); err != nil {
		return chall, fmt.Errorf("could not unmarshall JSON, error: %v", err)
	}
	return chall, nil
}

// internal struct defining the final response from Alice to Bob for SIGMA protocol
type responseMsg struct {
	Certificate certauth.ValidatedCertificate `json:"cert"` // Alice's validated certificate c_a
	Sig         []byte                        `json:"sig"`  // Alice's signature σ_a
	Mac         []byte                        `json:"mac"`  // Alice's HMAC µ_a
}

func (r responseMsg) marshal() []byte {
	data, err := json.Marshal(r)
	if err != nil {
		panic("could not marshal response message") // should never happen
	}
	return data
}

func unmarshalResponse(data []byte) (responseMsg, error) {
	var resp responseMsg
	if err := json.Unmarshal(data, &resp); err != nil {
		return resp, fmt.Errorf("could not unmarshall JSON, error: %v", err)
	}
	return resp, nil
}
