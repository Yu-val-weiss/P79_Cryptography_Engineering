package certauth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
)

// internal interface defining the data structs that are sent to/from the certificate authority
type certAuthData interface{ Marshal() []byte }

// Base certificate struct containing Name, start and end timestaps for validity, and the public key
type Certificate struct {
	Name      string            `json:"name"`       // name of the entity/user who's certificate it is
	Start     time.Time         `json:"start"`      // start time of the validity (i.e. when the certificate was registered)
	End       time.Time         `json:"end"`        // end time of the validity (expiry time)
	PublicKey ed25519.PublicKey `json:"public_key"` // the entity/user's public key
}

// creates a new [Certificate] from the name and public key which is of [ed25519.PublicKey]
func NewCertificate(name string, public_key ed25519.PublicKey) Certificate {
	t := time.Now()
	return Certificate{
		Name:      name,
		Start:     t,
		End:       t.AddDate(0, 6, 0),       // 6 month duration
		PublicKey: slices.Clone(public_key), // clone to prevent modification of the certificate via the slice
	}
}

// clones a certificate, convenience method for some testing
//
// start and end do not need cloning as they are copied by value
func (c Certificate) clone() Certificate {
	return Certificate{
		Name:      strings.Clone(c.Name),
		Start:     c.Start,
		End:       c.End,
		PublicKey: slices.Clone(c.PublicKey), // clone to prevent modification of the certificate via the slice
	}
}

// wraps [json.Marshal] into a convenient method receiver to convert a [Certificate] to bytes
func (c Certificate) Marshal() []byte {
	data, err := json.Marshal(c)
	if err != nil {
		panic("could not marshal certificate") // should never happen
	}
	return data
}

// Tests equality of two certificatess
func (c1 Certificate) Equal(c2 Certificate) bool {
	return c1.Name == c2.Name && c1.Start.Equal(c2.Start) && c1.End.Equal(c2.End) && bytes.Equal(c1.PublicKey, c2.PublicKey)
}

// promoted type for when a [Certificate] has been validated and signed by a [CertificateAuthority]
type ValidatedCertificate struct {
	Cert Certificate `json:"cert"`
	Sig  []byte      `json:"sig"` // signature (on marhsalled version of cert)
}

// wraps [json.Marshal] into a convenient method receiver to convert a [ValidatedCertificate] to bytes
func (c ValidatedCertificate) Marshal() []byte {
	data, err := json.Marshal(c)
	if err != nil {
		panic("could not marshal certificate") // should never happen
	}
	return data
}

// a request type to transmit to the certificate authority
type registerRequest struct {
	Name      string            `json:"name"`
	PublicKey ed25519.PublicKey `json:"pk"`
}

// wraps [json.Marshal] into a convenient method receiver to convert a [registerRequest] to bytes
func (r registerRequest) Marshal() []byte {
	data, err := json.Marshal(r)
	if err != nil {
		panic("could not marshal register request") // should never happen
	}
	return data
}

// create the data for a registration request to the certification authority
func MakeRegistrationRequest(name string, publicKey ed25519.PublicKey) []byte {
	return registerRequest{name, publicKey}.Marshal()
}

// generic unmarshaller for json bytes -> struct
//
// only works for the public types [Certificate] and [ValidatedCertificate]
//
// also works for the unexported type [registerRequest]
func Unmarshal[T certAuthData](data []byte) (T, error) {
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		return v, fmt.Errorf("could not unmarshall JSON, error: %v", err)
	}
	return v, nil
}

// Public type for a certificate authority, hiding local implementation
//
// doing it like this prevents creation of the struct
type CertificateAuthority = *certAuth

// hidden struct implementation for certificate authority
type certAuth struct {
	regcerts    map[string]Certificate
	authPubKey  ed25519.PublicKey
	authPrivKey ed25519.PrivateKey
}

// initialises a new [CertificateAuthority]
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

// registers a name and public key with the certificate authority and returns a byte array encoding a [Certificate]
//
// input is bytes representation of a registration request
//
// if the registration already exists and is still valid, and this method is called with the same public key
// then behaviour is idempotent and simply returns the existing certificate, without extending the validity
//
// to retrieve the certificate:
//
//	data, _ := ca.Certify("alice")
//	cert, err := certauth.Unmarshal[Certificate](data)
func (ca CertificateAuthority) Register(data []byte) []byte {
	req, err := Unmarshal[registerRequest](data)
	if err != nil {
		return nil
	}

	exist_cert, exists := ca.regcerts[req.Name]
	if exists && bytes.Equal(exist_cert.PublicKey, req.PublicKey) {
		return exist_cert.Marshal() // cannot re-register with the same public key, so return existing one
	}
	// either doesn't exist or new public key, so create a new certificate
	cert := NewCertificate(req.Name, req.PublicKey)
	ca.regcerts[req.Name] = cert

	// return clone of the certificate to prevent modification of the map via the slice
	return cert.Marshal()
}

// If there is a certificate registered under the input name, return a byte array encoding a [ValidatedCertificate] signed by the CA
//
// otherwise, returns nil and an error
//
// to retrieve the validated certificate:
//
//	data, _ := ca.Certify("alice")
//	val_cert, err := certauth.Unmarshal[ValidatedCertificate](data)
func (ca CertificateAuthority) Certify(name string) ([]byte, error) {
	cert, ok := ca.regcerts[name]
	if !ok {
		return nil, fmt.Errorf("name '%v' does not have a registered certificate", name)
	}
	if !time.Now().Before(cert.End) {
		return nil, fmt.Errorf("certificate has expired at '%v' for name '%v'", cert.End, name)
	}
	cert_json, err := json.Marshal(cert)
	if err != nil {
		return nil, fmt.Errorf("could not encode certificate to JSON, error: %v", err)
	}
	sig := ed25519.Sign(ca.authPrivKey, cert_json)
	val_cert := ValidatedCertificate{Cert: cert, Sig: sig}
	return val_cert.Marshal(), nil
}

// given a byte encoding of a [ValidatedCertificate],
// re-check the validity of the certificate (e.g. expiry) and the accompanying signature with the certificate authority
//
// to send the byte encoding use:
//
//	cert.Marshal()
func (ca CertificateAuthority) VerifyCertificate(data []byte) bool {
	vc, err := Unmarshal[ValidatedCertificate](data)

	if err != nil { // i.e. data is invalid for validated certificate
		return false
	}

	// check if the certificate is registered
	storedCert, exists := ca.regcerts[vc.Cert.Name]

	// check certificate matches registry, and is not expired, and the signature matches
	return exists && vc.Cert.Equal(storedCert) && time.Now().Before(vc.Cert.End) && ed25519.Verify(ca.authPubKey, vc.Cert.Marshal(), vc.Sig)
}
