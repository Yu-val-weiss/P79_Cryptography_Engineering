package sigma

import (
	"encoding/json"
	"fmt"

	certauth "github.com/yu-val-weiss/p79_cryptography_engineering/lab2/cert_auth"
)

// internal interface defining the data structs that are sent to/from the certificate authority
type message interface{ Marshal() []byte }

// internal struct defining challenge message (Bob -> Alice) for SIGMA protocol
type challengeMsg struct {
	Challenge   []byte                        `json:"challenge"` // Bob's challenge g**y to Alice's commitment g**x
	Certificate certauth.ValidatedCertificate `json:"cert"`      // Bob's validated certificate c_b
	Sig         []byte                        `json:"sig"`       // Bob's signature σ_b
	Mac         []byte                        `json:"mac"`       // Bob's HMAC µ_b
}

// Marshal a [challengeMsg] to json bytes
func (r challengeMsg) Marshal() []byte {
	data, err := json.Marshal(r)
	if err != nil {
		panic("could not marshal commitment message") // should never happen
	}
	return data
}

// internal struct defining the final response from Alice to Bob for SIGMA protocol
type responseMsg struct {
	Certificate certauth.ValidatedCertificate `json:"cert"` // Alice's validated certificate c_a
	Sig         []byte                        `json:"sig"`  // Alice's signature σ_a
	Mac         []byte                        `json:"mac"`  // Alice's HMAC µ_a
}

// Marshal a [responseMsg] to json bytes
func (r responseMsg) Marshal() []byte {
	data, err := json.Marshal(r)
	if err != nil {
		panic("could not marshal response message") // should never happen
	}
	return data
}

// convert json bytes to [message] (either [challengeMsg] or [responseMsg])
func unmarshal[T message](data []byte) (T, error) {
	var msg T
	if err := json.Unmarshal(data, &msg); err != nil {
		return msg, fmt.Errorf("could not unmarshall JSON, error: %v", err)
	}
	return msg, nil
}
