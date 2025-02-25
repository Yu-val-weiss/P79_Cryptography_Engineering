package certauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"slices"
	"time"
)

type Certificate struct {
	Name      string            `json:"name"`
	Start     time.Time         `json:"start"`
	End       time.Time         `json:"end"`
	PublicKey ed25519.PublicKey `json:"public_key"`
}

func NewCertificate(name string, public_key ed25519.PublicKey) Certificate {
	t := time.Now()
	return Certificate{
		Name:      name,
		Start:     t,
		End:       t.AddDate(0, 6, 0), // 6 month duration
		PublicKey: public_key,
	}
}

type CertificateAuthority struct {
	RegCerts    map[string]Certificate `json:"registered_certificates"`
	AuthPubKey  ed25519.PublicKey      `json:"authority_public_key"`
	authprivkey ed25519.PrivateKey
}

func NewAuthority() *CertificateAuthority {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("failed to instantiate authority due to error %v", err))
	}
	return &CertificateAuthority{
		RegCerts:    make(map[string]Certificate),
		AuthPubKey:  pub,
		authprivkey: priv,
	}
}

func (ca *CertificateAuthority) RegisterCertificate(name string, public_key ed25519.PublicKey) Certificate {
	cert := NewCertificate(name, public_key)
	ca.RegCerts[name] = cert

	// return copy of the certificate to prevent modification of the map with the slice
	return Certificate{
		Name:      cert.Name,
		Start:     cert.Start,
		End:       cert.End,
		PublicKey: slices.Clone(cert.PublicKey), // defensive copy
	}
}
