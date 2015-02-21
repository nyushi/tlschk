package tlschk

import "crypto/tls"

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
