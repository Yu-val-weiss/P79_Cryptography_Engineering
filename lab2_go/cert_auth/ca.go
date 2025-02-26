package certauth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
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
		End:       t.AddDate(0, 6, 0),       // 6 month duration
		PublicKey: slices.Clone(public_key), // clone to prevent modification of the certificate via the slice
	}
}

func (c Certificate) clone() Certificate {
	return Certificate{
		Name:      c.Name,
		Start:     c.Start,
		End:       c.End,
		PublicKey: slices.Clone(c.PublicKey), // clone to prevent modification of the certificate via the slice
	}
}

func (c Certificate) Marshal() []byte {
	data, err := json.Marshal(c)
	if err != nil {
		panic("could not marshal certificate") // should never happen
	}
	return data
}

// Unmarshals the byte data to a certificate
func UnmarshalCertificate(data []byte) (Certificate, error) {
	var cert Certificate
	if err := json.Unmarshal(data, &cert); err != nil {
		return cert, fmt.Errorf("could not unmarshall JSON, error: %v", err)
	}
	return cert, nil
}

type ValidatedCertificate struct {
	Cert Certificate
	Sig  []byte // signature (on marhsalled version of cert)
}

type CertificateAuthority struct {
	regcerts    map[string]Certificate
	AuthPubKey  ed25519.PublicKey
	authprivkey ed25519.PrivateKey
}

func NewAuthority() *CertificateAuthority {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(fmt.Sprintf("failed to instantiate authority due to error %v", err))
	}
	return &CertificateAuthority{
		regcerts:    make(map[string]Certificate),
		AuthPubKey:  pub,
		authprivkey: priv,
	}
}

func (ca *CertificateAuthority) RegisterCertificate(name string, public_key ed25519.PublicKey) Certificate {
	exist_cert, exists := ca.regcerts[name]
	if exists && bytes.Equal(exist_cert.PublicKey, public_key) {
		return exist_cert.clone() // cannot re-register with the same public key, so return existing one
	}
	// either doesn't exist or new public key, so create a new certificate
	cert := NewCertificate(name, public_key)
	ca.regcerts[name] = cert

	// return clone of the certificate to prevent modification of the map via the slice
	return cert.clone()
}

func (ca *CertificateAuthority) GetCertificate(name string) (Certificate, error) {
	cert, ok := ca.regcerts[name]
	if !ok {
		return Certificate{}, fmt.Errorf("name '%v' does not have a registered certificate", name)
	}
	return cert, nil
}

// returns JSON marshalled (bytes) certificate, signature, and error
// should be unmarshalled with [UnmarshalCertificate].
func (ca *CertificateAuthority) Certify(name string) (ValidatedCertificate, error) {
	cert, ok := ca.regcerts[name]
	if !ok {
		return ValidatedCertificate{}, fmt.Errorf("name '%v' does not have a registered certificate", name)
	}
	if !time.Now().Before(cert.End) {
		return ValidatedCertificate{}, fmt.Errorf("certificate has expired at '%v' for name '%v'", cert.End, name)
	}
	cert_json, err := json.Marshal(cert)
	if err != nil {
		return ValidatedCertificate{}, fmt.Errorf("could not encode certificate to JSON, error: %v", err)
	}
	sig := ed25519.Sign(ca.authprivkey, cert_json)
	return ValidatedCertificate{Cert: cert, Sig: sig}, nil
}

func (ca *CertificateAuthority) VerifyCertificate(vc ValidatedCertificate) bool {
	// verify signature first
	if !ed25519.Verify(ca.AuthPubKey, vc.Cert.Marshal(), vc.Sig) {
		fmt.Println("here!")
		return false
	}

	// check if the certificate is registered
	storedCert, exists := ca.regcerts[vc.Cert.Name]
	if !exists {
		return false
	}

	// ensure the certificate hasn't expired
	if time.Now().After(vc.Cert.End) {
		return false
	}

	// validate the public key matches
	if !bytes.Equal(storedCert.PublicKey, vc.Cert.PublicKey) {
		return false // Public key mismatch
	}

	// all checks passed, so return true
	return true
}
