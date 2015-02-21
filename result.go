package tlschk

import "crypto/tls"

// Result represents check result
type Result struct {
	Result  string   `json:"result"`
	Detail  string   `json:"detail"`
	Recv    *string  `json:"recv,omitempty"`
	TLSInfo *tlsInfo `json:"tls_info,omitempty"`
}

type tlsInfo struct {
	Version       string        `json:"version"`
	Cipher        string        `json:"cipher"`
	ReceivedCerts []certificate `json:"received_certs"`
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
