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

func (c1 Certificate) equal(c2 Certificate) bool {
	return c1.Name == c2.Name && c1.Start.Equal(c2.Start) && c1.End.Equal(c2.End) && bytes.Equal(c1.PublicKey, c2.PublicKey)
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

// publicly exported certificate authority type
type CertificateAuthority = *certAuth

// hidden struct implementation
type certAuth struct {
	regcerts    map[string]Certificate
	authPubKey  ed25519.PublicKey
	authPrivKey ed25519.PrivateKey
}

func NewAuthority() CertificateAuthority {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(fmt.Sprintf("failed to instantiate authority due to key gen error %v", err))
	}
	return &certAuth{
		regcerts:    make(map[string]Certificate),
		authPubKey:  pub,
		authPrivKey: priv,
	}
}

// registers a name and public key with the certificate authority and returns a [Certificate]
//
// if the registration already exists and is still valid, and this method is called with the same public key
// then behaviour is idempotent and simply returns the existing certificate, without extending the validity
func (ca CertificateAuthority) Register(name string, public_key ed25519.PublicKey) Certificate {
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

// returns [ValidatedCertificate] and (possibly nil) error
// should be unmarshalled with [UnmarshalCertificate].
func (ca CertificateAuthority) Certify(name string) (ValidatedCertificate, error) {
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
	sig := ed25519.Sign(ca.authPrivKey, cert_json)
	return ValidatedCertificate{Cert: cert, Sig: sig}, nil
}

func (ca CertificateAuthority) VerifyCertificate(vc ValidatedCertificate) bool {
	// check if the certificate is registered
	storedCert, exists := ca.regcerts[vc.Cert.Name]

	// check certificate matches registry, and is not expired, and the signature matches
	return exists && vc.Cert.equal(storedCert) && time.Now().Before(vc.Cert.End) && ed25519.Verify(ca.authPubKey, vc.Cert.Marshal(), vc.Sig)
}
