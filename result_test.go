package tlschk

import (
	"crypto/tls"
	"errors"
	"testing"
)

func TestNewResultSimple(t *testing.T) {
	r := NewResult(errors.New("test error"), nil)

	if r.Result != "NG" {
		t.Errorf("r.Result is %q, want NG", r.Result)
	}
	if r.Detail != "test error" {
		t.Errorf("r.Detail is %q, want \"test error\"", r.Detail)
	}

	r = NewResult(nil, nil)

	if r.Result != "OK" {
		t.Errorf("r.Result is %q, want OK", r.Result)
	}
	if r.Detail != "" {
		t.Errorf("r.Detail is %q, want \"\"", r.Detail)
	}
}

type csGetter struct {
	cs tls.ConnectionState
}

func (c csGetter) ConnectionState() tls.ConnectionState {
	return c.cs
}

func TestNewResultWithTLSInfo(t *testing.T) {
	c := csGetter{
		tls.ConnectionState{
			Version:     tls.VersionTLS12,
			CipherSuite: tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
	}
	r := NewResult(nil, c)
	if r.Result != "OK" {
		t.Errorf("r.Result is %q, want OK", r.Result)
	}
	if r.Detail != "" {
		t.Errorf("r.Detail is %q, want \"\"", r.Detail)
	}
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
