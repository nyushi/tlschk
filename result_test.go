package tlschk

import (
	"crypto/tls"
	"errors"
	"net"
	"testing"
)

func TestResultSetError(t *testing.T) {
	r := &Result{}

	r.SetError(errors.New("test error"))

	if r.Result != "NG" {
		t.Errorf("r.Result is %q, want NG", r.Result)
	}
	if r.Detail != "test error" {
		t.Errorf("r.Detail is %q, want \"test error\"", r.Detail)
	}
}

type raGetter struct {
	ra net.Addr
}

func (r raGetter) RemoteAddr() net.Addr {
	return r.ra
}

type dummyAddr struct {
	net string
	str string
}

func (da dummyAddr) Network() string {
	return da.net
}

func (da dummyAddr) String() string {
	return da.str
}

func TestResultSetConnectionInfo(t *testing.T) {
	r := &Result{}
	r.SetConnectionInfo(nil, 1)
	if r.ConnectionInfo != nil {
		t.Error("r.ConnectionInfo is not nil, want nil")
	}

	s := &raGetter{ra: dummyAddr{"", "127.0.0.1:443"}}
	r.SetConnectionInfo(s, 1)

	if r.ConnectionInfo == nil {
		t.Error("r.ConnectionInfo is nil, want not nil")
	}
	a := "127.0.0.1"
	if r.ConnectionInfo.IPAddress != a {
		t.Errorf("r.ConnectionInfo.IPAddress is %q, want %q", r.ConnectionInfo.IPAddress, a)
	}
	p := 443
	if r.ConnectionInfo.Port != p {
		t.Errorf("r.ConnectionInfo.Port is %q, want %q", r.ConnectionInfo.Port, p)
	}
	e := float64(1)
	if r.ConnectionInfo.Elapsed != e {
		t.Errorf("r.ConnectionInfo.Elapsed is %f, want %f", r.ConnectionInfo.Elapsed, e)
	}
}

type csGetter struct {
	cs tls.ConnectionState
}

func (c csGetter) ConnectionState() tls.ConnectionState {
	return c.cs
}

func TestResultSetTLSInfo(t *testing.T) {
	c := csGetter{
		tls.ConnectionState{
			Version:     tls.VersionTLS12,
			CipherSuite: tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
	}
	r := &Result{}
	r.SetTLSInfo(nil, 1)
	if r.TLSInfo != nil {
		t.Errorf("r.TLSInfo is not nil, want nil")
	}
	r.SetTLSInfo(c, 1)
	if r.TLSInfo == nil {
		t.Errorf("r.TLSInfo is nil, want not nil")
	}
	if r.TLSInfo.Version != "TLS1.2" {
		t.Errorf("r.TLSInfo.Version is %q not TLS1.2", r.TLSInfo.Version)
	}
	if r.TLSInfo.Cipher != "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" {
		t.Errorf("r.TLSInfo.Cipher is %q not TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", r.TLSInfo.Cipher)
	}
	if r.TLSInfo.Elapsed != float64(1) {
		t.Errorf("r.TLSInfo.Cipher is %q not %f", r.TLSInfo.Cipher, float64(1))
	}
}

func TestSetTrustedChains(t *testing.T) {
	r := Result{}
	chains := [][]*Cert{[]*Cert{
		&Cert{leaf.X509Cert, false, ""},
		&Cert{chain.X509Cert, false, ""},
		&Cert{root.X509Cert, false, ""}}}
	r.SetTrustedChains(chains)
	if r.TLSInfo != nil {
		t.Error("r.TLSInfo is not nil, want nil")
	}

	r.TLSInfo = &ResultTLSInfo{}
	r.SetTrustedChains(chains)
	if r.TLSInfo == nil {
		t.Error("r.TLSInfo is nil, want not nil")
	}
	if len(r.TLSInfo.TrustedChains) != 1 {
		t.Errorf("r.TLSInfo.TrustedChains len is %q, want 1", len(r.TLSInfo.TrustedChains))
	}
	if len(r.TLSInfo.TrustedChains[0]) != 3 {
		t.Errorf("r.TLSInfo.TrustedChains[0] len is %q, want 3", len(r.TLSInfo.TrustedChains))
	}
}

func TestResultUpdateTLSInfo(t *testing.T) {
	r := &Result{}
	r.UpdateTLSInfo(nil)
	if r.TLSInfo != nil {
		t.Error("r.TLSInfo is not nil, want nil")
	}

	c := &Cert{root.X509Cert, false, ""}
	r.TLSInfo = &ResultTLSInfo{
		ReceivedCerts: []CertSummary{
			c.Summary(),
		},
	}
	// modify
	r.TLSInfo.ReceivedCerts[0].Error = "some error"
	r.TLSInfo.ReceivedCerts[0].Revoked = true

	r.UpdateTLSInfo([][]*Cert{{c}})
	// returned
	if r.TLSInfo.ReceivedCerts[0].Error != "" {
		t.Errorf("r.TLSInfo.ReceivedCerts[0].Error is %q, want \"\"", r.TLSInfo.ReceivedCerts[0].Error)
	}
	if r.TLSInfo.ReceivedCerts[0].Revoked != false {
		t.Error("r.TLSInfo.ReceivedCerts[0].Revoked is true, want false")
	}

}
