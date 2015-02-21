package tlschk

import (
	"crypto/tls"
	"testing"
)

func TestTLSVersion(t *testing.T) {
	tests := []struct {
		a uint16
		b string
	}{
		{tls.VersionSSL30, "SSL3.0"},
		{tls.VersionTLS10, "TLS1.0"},
		{tls.VersionTLS11, "TLS1.1"},
		{tls.VersionTLS12, "TLS1.2"},
	}
	for _, test := range tests {
		s := TLSVersionString(test.a)
		if s != test.b {
			t.Errorf("TLSVersionString returns %q, want %q", s, test.b)
		}
		i := TLSVersionInt(test.b)
		if i != test.a {
			t.Errorf("TLSVersionInt returns %q, want %q", i, test.a)
		}
	}

	s := TLSVersionString(12345)
	if s != "" {
		t.Errorf("TLSVersionString returns %q, want \"\"", s)
	}

	i := TLSVersionInt("")
	if i != 0 {
		t.Errorf("TLSVersionInt returns %q, want 0", i)
	}
}

func TestTLSCipher(t *testing.T) {
	tests := []struct {
		a uint16
		b string
	}{
		{tls.TLS_RSA_WITH_RC4_128_SHA, "TLS_RSA_WITH_RC4_128_SHA"},
		{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
		{tls.TLS_RSA_WITH_AES_128_CBC_SHA, "TLS_RSA_WITH_AES_128_CBC_SHA"},
		{tls.TLS_RSA_WITH_AES_256_CBC_SHA, "TLS_RSA_WITH_AES_256_CBC_SHA"},
		{tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"},
		{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"},
		{tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"},
		{tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA, "TLS_ECDHE_RSA_WITH_RC4_128_SHA"},
		{tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"},
		{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"},
		{tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"},
		{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
	}
	for _, test := range tests {
		s := TLSCipherString(test.a)
		if s != test.b {
			t.Errorf("TLSCipherString returns %q, want %q", s, test.b)
		}
		i := TLSCipherInt(test.b)
		if i != test.a {
			t.Errorf("TLSCipherInt returns %q, want %q", i, test.a)
		}
	}

	s := TLSCipherString(12345)
	if s != "" {
		t.Errorf("TLSCipherString returns %q, want \"\"", s)
	}
	i := TLSCipherInt("")
	if i != 0 {
		t.Errorf("TLSCipherInt returns %q, want 0", i)
	}
}
