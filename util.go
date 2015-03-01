package tlschk

import (
	"crypto/tls"
	"crypto/x509"
)

var (
	tlsVersionUInt16s = []uint16{
		tls.VersionSSL30,
		tls.VersionTLS10,
		tls.VersionTLS11,
		tls.VersionTLS12,
	}
	tlsVersionStrings = []string{
		"SSL3.0",
		"TLS1.0",
		"TLS1.1",
		"TLS1.2",
	}

	tlsCipherUInt16s = []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	}
	tlsCipherStrings = []string{
		"TLS_RSA_WITH_RC4_128_SHA",
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_RSA_WITH_AES_128_CBC_SHA",
		"TLS_RSA_WITH_AES_256_CBC_SHA",
		"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_RC4_128_SHA",
		"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	}

	x509SignatureAlgorithms = []x509.SignatureAlgorithm{
		x509.MD2WithRSA,
		x509.MD5WithRSA,
		x509.SHA1WithRSA,
		x509.SHA256WithRSA,
		x509.SHA384WithRSA,
		x509.SHA512WithRSA,
		x509.DSAWithSHA1,
		x509.DSAWithSHA256,
		x509.ECDSAWithSHA1,
		x509.ECDSAWithSHA256,
		x509.ECDSAWithSHA384,
		x509.ECDSAWithSHA512,
	}
	x509SignatureAlgorithmStrings = []string{
		"MD2WithRSA",
		"MD5WithRSA",
		"SHA1WithRSA",
		"SHA256WithRSA",
		"SHA384WithRSA",
		"SHA512WithRSA",
		"DSAWithSHA1",
		"DSAWithSHA256",
		"ECDSAWithSHA1",
		"ECDSAWithSHA256",
		"ECDSAWithSHA384",
		"ECDSAWithSHA512",
	}
)

// TLSVersionString returns version string from uint16 value
func TLSVersionString(v uint16) string {
	for i, ver := range tlsVersionUInt16s {
		if v == ver {
			return tlsVersionStrings[i]
		}
	}
	return ""
}

// TLSVersionInt returns version uint16 from string value
func TLSVersionInt(v string) uint16 {
	for i, ver := range tlsVersionStrings {
		if v == ver {
			return tlsVersionUInt16s[i]
		}
	}
	return 0
}

// TLSCipherString returns version string from uint16 value
func TLSCipherString(v uint16) string {
	for i, ver := range tlsCipherUInt16s {
		if v == ver {
			return tlsCipherStrings[i]
		}
	}
	return ""
}

// TLSCipherInt returns version uint16 from string value
func TLSCipherInt(v string) uint16 {
	for i, ver := range tlsCipherStrings {
		if v == ver {
			return tlsCipherUInt16s[i]
		}
	}
	return 0
}

// X509SignatureAlgorithmString returns string from SignatureAlgorigm
func X509SignatureAlgorithmString(v x509.SignatureAlgorithm) string {
	for i, algo := range x509SignatureAlgorithms {
		if v == algo {
			return x509SignatureAlgorithmStrings[i]
		}
	}
	return ""
}

// X509SignatureAlgorithm returns SignatureAlgorigm from string value
func X509SignatureAlgorithm(v string) x509.SignatureAlgorithm {
	for i, algo := range x509SignatureAlgorithmStrings {
		if v == algo {
			return x509SignatureAlgorithms[i]
		}
	}
	return 0
}
