package tlschk

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/x509"
	"fmt"
	"hash"
)

// CertSummary represents certificate summary
type CertSummary struct {
	Subject         string   `json:"subject"`
	SubjectAltNames []string `json:"subject_alt_names"`
	Issuer          string   `json:"issuer"`
	MD5             string   `json:"md5"`
	SHA1            string   `json:"sha1"`
	NotAfter        int64    `json:"not_after"`
	NotBefore       int64    `json:"not_before"`
	Revoked         bool     `json:"revoked"`
	Error           string   `json:"warn"`
}

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

// Summary returns certificate summary
func (c *Cert) Summary() CertSummary {
	return CertSummary{
		Subject:         c.Subject.CommonName,
		SubjectAltNames: c.DNSNames,
		Issuer:          c.Issuer.CommonName,
		MD5:             c.Fingerprint(md5.New()),
		SHA1:            c.Fingerprint(sha1.New()),
		NotAfter:        c.NotAfter.Unix(),
		NotBefore:       c.NotBefore.Unix(),
		Revoked:         c.Revoked,
		Error:           c.Error,
	}
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
