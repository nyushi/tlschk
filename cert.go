package tlschk

import (
	"crypto/x509"
	"fmt"
	"hash"
)

// Cert is wrapper for x509.Certificate
type Cert struct {
	*x509.Certificate
	Revoked bool
	Error   string
}

// Fingerprint returns hash string for certificate
func (c *Cert) Fingerprint(h hash.Hash) string {
	h.Write(c.Raw)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// CertChain is wrapper for []x509.Certificate
type CertChain []*Cert

// NewCertChain returns CeetChain from []*x509.Certificate
func NewCertChain(x509chain []*x509.Certificate) CertChain {
	c := make([]*Cert, len(x509chain))
	for i, v := range x509chain {
		c[i] = &Cert{v, false, ""}
	}
	return c
}

// CheckRevocation updates revoked field
func (cc CertChain) CheckRevocation() {
	for j, cert := range cc {
		issuerIdx := j + 1
		if j+1 == len(cc) {
			issuerIdx = j
		}
		revoked := isRevokedCert(cert.Certificate, cc[issuerIdx].Certificate)
		cert.Revoked = revoked
	}
}

// IsRevoked returns true when chain is revoked
func (cc CertChain) IsRevoked() bool {
	for _, c := range cc {
		if c.Revoked {
			return true
		}
	}
	return false
}
