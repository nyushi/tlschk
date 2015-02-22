package tlschk

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
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
	r.SetTLSInfo(c)
	if r.TLSInfo == nil {
		t.Errorf("r.TLSInfo is nil, want not nil")
	}
	if r.TLSInfo.Version != "TLS1.2" {
		t.Errorf("r.TLSInfo.Version is %q not TLS1.2", r.TLSInfo.Version)
	}
	if r.TLSInfo.Cipher != "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" {
		t.Errorf("r.TLSInfo.Cipher is %q not TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", r.TLSInfo.Cipher)
	}
}

func TestSetTrustedChains(t *testing.T) {
	r := Result{}
	chains := [][]*x509.Certificate{[]*x509.Certificate{leaf.X509Cert, chain.X509Cert, root.X509Cert}}
	r.SetTrustedChains(chains)
	if r.TLSInfo != nil {
		t.Errorf("r.TLSInfo is %q, want nil", chains)
	}

	r.TLSInfo = &tlsInfo{}
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
