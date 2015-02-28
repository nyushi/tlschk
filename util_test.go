package tlschk

import (
	"crypto/tls"
	"crypto/x509"
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

func TestX509SignatureAlgorithm(t *testing.T) {
	tests := []struct {
		a x509.SignatureAlgorithm
		b string
	}{
		{x509.MD2WithRSA, "MD2WithRSA"},
		{x509.MD5WithRSA, "MD5WithRSA"},
		{x509.SHA1WithRSA, "SHA1WithRSA"},
		{x509.SHA256WithRSA, "SHA256WithRSA"},
		{x509.SHA384WithRSA, "SHA384WithRSA"},
		{x509.SHA512WithRSA, "SHA512WithRSA"},
		{x509.DSAWithSHA1, "DSAWithSHA1"},
		{x509.DSAWithSHA256, "DSAWithSHA256"},
		{x509.ECDSAWithSHA1, "ECDSAWithSHA1"},
		{x509.ECDSAWithSHA256, "ECDSAWithSHA256"},
		{x509.ECDSAWithSHA384, "ECDSAWithSHA384"},
		{x509.ECDSAWithSHA512, "ECDSAWithSHA512"},
	}
	for _, test := range tests {
		s := X509SignatureAlgorithmString(test.a)
		if s != test.b {
			t.Errorf("X509SignatureAlgorithmString returns %q, want %q", s, test.b)
		}
		i := X509SignatureAlgorithm(test.b)
		if i != test.a {
			t.Errorf("X509SignatureAlgorithm returns %q, want %q", i, test.a)
		}
	}

	s := X509SignatureAlgorithmString(12345)
	if s != "" {
		t.Errorf("X509SignatureAlgorithmString returns %q, want \"\"", s)
	}
	i := X509SignatureAlgorithm("")
	if i != 0 {
		t.Errorf("X509SignatureAlgorithm returns %q, want 0", i)
	}
}
