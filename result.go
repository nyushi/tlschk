package tlschk

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"hash"
	"net"
	"strconv"
)

// Result represents check result
type Result struct {
	Result         string          `json:"result"`
	Detail         string          `json:"detail"`
	Recv           *string         `json:"recv,omitempty"`
	TLSInfo        *tlsInfo        `json:"tls_info,omitempty"`
	ConnectionInfo *connectionInfo `json:"connection_info,omitempty"`
}

type connectionInfo struct {
	IPAddress string `json:"ip_address"`
	Port      int    `json:"port"`
}

type tlsInfo struct {
	Version       string          `json:"version"`
	Cipher        string          `json:"cipher"`
	ReceivedCerts []certSummary   `json:"received_certs"`
	TrustedChains [][]certSummary `json:"trusted_chains"`
}

type certSummary struct {
	Subject         string   `json:"subject"`
	SubjectAltNames []string `json:"subject_alt_names"`
	Issuer          string   `json:"issuer"`
	MD5             string   `json:"md5"`
	SHA1            string   `json:"sha1"`
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
func (r *Result) SetConnectionInfo(c remoteAddrGetter) {
	if c == nil {
		return
	}
	host, port, _ := net.SplitHostPort(c.RemoteAddr().String())
	portInt, _ := strconv.Atoi(port)
	r.ConnectionInfo = &connectionInfo{IPAddress: host, Port: portInt}
}

// SetTLSInfo set tlsinfo
func (r *Result) SetTLSInfo(c connectionStateGetter) {
	if c == nil {
		return
	}
	connState := c.ConnectionState()
	r.TLSInfo = &tlsInfo{
		Version: TLSVersionString(connState.Version),
		Cipher:  TLSCipherString(connState.CipherSuite),
	}

	r.TLSInfo.ReceivedCerts = make([]certSummary, len(connState.PeerCertificates))
	for i, cert := range connState.PeerCertificates {
		r.TLSInfo.ReceivedCerts[i] = getCertSummary(cert)
	}
}

// SetTrustedChains set trusted certificate chains
func (r *Result) SetTrustedChains(chains [][]*x509.Certificate) {
	if r.TLSInfo == nil {
		return
	}

	r.TLSInfo.TrustedChains = make([][]certSummary, len(chains))
	for i, chain := range chains {
		r.TLSInfo.TrustedChains[i] = make([]certSummary, len(chain))
		for j, cert := range chain {
			r.TLSInfo.TrustedChains[i][j] = getCertSummary(cert)
		}
	}
}

func fingerprint(c *x509.Certificate, h hash.Hash) string {
	h.Write(c.Raw)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func getCertSummary(cert *x509.Certificate) certSummary {
	return certSummary{
		Subject:         cert.Subject.CommonName,
		SubjectAltNames: cert.DNSNames,
		Issuer:          cert.Issuer.CommonName,
		MD5:             fingerprint(cert, md5.New()),
		SHA1:            fingerprint(cert, sha1.New()),
	}
}
