package certstore

import (
	"crypto/x509"
	"encoding/pem"
)

// CertificateResource represent everything from our cert
type CertificateResource struct {
	Domain            string `json:"domain"`
	PrivateKey        []byte `json:"key"`
	Certificate       []byte `json:"certificate"`
	IssuerCertificate []byte `json:"issuer"`
}

func (c *CertificateResource) parseCert() (*x509.Certificate, error) {
	block, _ := pem.Decode(c.Certificate)
	return x509.ParseCertificate(block.Bytes)
}
