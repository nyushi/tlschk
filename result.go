package tlschk

import (
	"crypto/tls"
	"crypto/x509"
)

// Result represents check result
type Result struct {
	Result  string   `json:"result"`
	Detail  string   `json:"detail"`
	Recv    *string  `json:"recv,omitempty"`
	TLSInfo *tlsInfo `json:"tls_info,omitempty"`
}

type tlsInfo struct {
	Version       string          `json:"version"`
	Cipher        string          `json:"cipher"`
	ReceivedCerts []certificate   `json:"received_certs"`
	TrustedChains [][]certificate `json:"trusted_chains"`
}

type certificate struct {
	Subject         string   `json:"subject"`
	SubjectAltNames []string `json:"subject_alt_names"`
	Issuer          string   `json:"issuer"`
}

type connectionStateGetter interface {
	ConnectionState() tls.ConnectionState
}

// NewResult returns Result
func NewResult(e error, c connectionStateGetter) *Result {
	r := Result{Result: "NG"}
	if e != nil {
		r.Detail = e.Error()
	} else {
		r.Result = "OK"
	}

	if c != nil {
		connState := c.ConnectionState()
		r.TLSInfo = &tlsInfo{
			Version: TLSVersionString(connState.Version),
			Cipher:  TLSCipherString(connState.CipherSuite),
		}
	}
	return &r
}

// SetTrustedChains set trusted certificate chains
func (r *Result) SetTrustedChains(chains [][]*x509.Certificate) {
	if r.TLSInfo == nil {
		return
	}

	r.TLSInfo.TrustedChains = make([][]certificate, len(chains))
	for i, chain := range chains {
		r.TLSInfo.TrustedChains[i] = make([]certificate, len(chain))
		for j, cert := range chain {
			r.TLSInfo.TrustedChains[i][j] = certificate{
				Subject:         cert.Subject.CommonName,
				SubjectAltNames: cert.DNSNames,
				Issuer:          cert.Issuer.CommonName,
			}
		}
	}
}
