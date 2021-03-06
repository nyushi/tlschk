package tlschk

import (
	"crypto/sha1"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
)

// Result represents check result
type Result struct {
	Result             string                    `json:"result"`
	Detail             string                    `json:"detail"`
	ConnectionInfo     *ResultConnectionInfo     `json:"connection_info,omitempty"`
	PlainRoundTripInfo *ResultPlainRoundTripInfo `json:"plain_round_trip_info,omitempty"`
	TLSInfo            *ResultTLSInfo            `json:"tls_info,omitempty"`
	TLSRoundTripInfo   *ResultTLSRoundTripInfo   `json:"tls_round_trip_info,omitempty"`
	Elapsed            float64                   `json:"elapsed"`
}

// ResultConnectionInfo represents result of connection
type ResultConnectionInfo struct {
	IPAddress string  `json:"ip_address"`
	Port      int     `json:"port"`
	Elapsed   float64 `json:"elapsed"`
}

// ResultPlainRoundTripInfo represents result of plain round trip
type ResultPlainRoundTripInfo struct {
	Received string  `json:"recv"`
	Elapsed  float64 `json:"elapsed"`
}

// ResultTLSRoundTripInfo represents result of tls round trip
type ResultTLSRoundTripInfo struct {
	Received string  `json:"recv"`
	Elapsed  float64 `json:"elapsed"`
}

// ResultTLSInfo represents result of tls
type ResultTLSInfo struct {
	Version       string          `json:"version"`
	Cipher        string          `json:"cipher"`
	ReceivedCerts []CertSummary   `json:"received_certs"`
	TrustedChains [][]CertSummary `json:"trusted_chains"`
	Elapsed       float64         `json:"elapsed"`
}

type connectionStateGetter interface {
	ConnectionState() tls.ConnectionState
}

type remoteAddrGetter interface {
	RemoteAddr() net.Addr
}

// SetError set error
func (r *Result) SetError(e error) {
	r.Result = "NG"
	r.Detail = e.Error()
}

// SetConnectionInfo set connection information
func (r *Result) SetConnectionInfo(c remoteAddrGetter, elapsed float64) {
	if c == nil {
		return
	}
	host, port, _ := net.SplitHostPort(c.RemoteAddr().String())
	portInt, _ := strconv.Atoi(port)
	r.ConnectionInfo = &ResultConnectionInfo{IPAddress: host, Port: portInt, Elapsed: elapsed}
}

// SetTLSInfo set tlsinfo
func (r *Result) SetTLSInfo(c connectionStateGetter, elapsed float64) {
	if c == nil {
		return
	}
	connState := c.ConnectionState()
	r.TLSInfo = &ResultTLSInfo{
		Version: TLSVersionString(connState.Version),
		Cipher:  TLSCipherString(connState.CipherSuite),
		Elapsed: elapsed,
	}

	r.TLSInfo.ReceivedCerts = make([]CertSummary, len(connState.PeerCertificates))
	for i, cert := range connState.PeerCertificates {
		c := &Cert{cert, false, ""}
		r.TLSInfo.ReceivedCerts[i] = c.Summary()
	}
}

// UpdateTLSInfo updates tls info by invalid certificate chains
func (r *Result) UpdateTLSInfo(invalidChains [][]*Cert) {
	if r.TLSInfo == nil {
		return
	}
	for _, chain := range invalidChains {
		for _, cert := range chain {
			for i, received := range r.TLSInfo.ReceivedCerts {
				if received.SHA1 == cert.Fingerprint(sha1.New()) {
					r.TLSInfo.ReceivedCerts[i] = cert.Summary()
				}
			}
		}
	}
}

// SetPlainRoundTripInfo set plainRoundTripInfo
func (r *Result) SetPlainRoundTripInfo(data string, elapsed float64) {
	r.PlainRoundTripInfo = &ResultPlainRoundTripInfo{
		Received: data,
		Elapsed:  elapsed,
	}
}

// SetTLSRoundTripInfo set tlsRoundTripInfo
func (r *Result) SetTLSRoundTripInfo(data string, elapsed float64) {
	r.TLSRoundTripInfo = &ResultTLSRoundTripInfo{
		Received: data,
		Elapsed:  elapsed,
	}
}

// SetTrustedChains set trusted certificate chains
func (r *Result) SetTrustedChains(chains [][]*Cert) {
	if r.TLSInfo == nil {
		return
	}

	if len(chains) == 0 {
		r.SetError(errors.New("TLS verify error. trusted chain not found"))
		return
	}
	r.TLSInfo.TrustedChains = make([][]CertSummary, len(chains))
	for i, chain := range chains {
		r.TLSInfo.TrustedChains[i] = make([]CertSummary, len(chain))
		for j, cert := range chain {
			r.TLSInfo.TrustedChains[i][j] = cert.Summary()
		}
	}
}
