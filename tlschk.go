package tlschk

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

func elapsed(from time.Time) float64 {
	return time.Now().Sub(from).Seconds()
}

// DoCheck starts tls check
func DoCheck(reader io.Reader) (r *Result) {
	r = &Result{Result: "OK"}
	t := time.Now()
	defer func() {
		r.Elapsed = elapsed(t)
	}()
	conf, err := LoadConfig(reader)
	if err != nil {
		r.SetError(err)
		return
	}

	var tt time.Time
	tt = time.Now()
	rawConn, err := connect(conf)
	if err != nil {
		r.SetError(err)
		return
	}
	defer rawConn.Close()
	tcpConn := rawConn.(*net.TCPConn)
	r.SetConnectionInfo(tcpConn, elapsed(tt))

	if conf.NeedPlainRoundTrip() {
		tt = time.Now()
		plainData, err := plainRoundTrip(conf, tcpConn)
		if err != nil {
			r.SetError(err)
			return
		}
		r.SetPlainRoundTripInfo(plainData, elapsed(tt))
	}

	tt = time.Now()
	tlsConn, err := startTLS(conf, rawConn)
	if err != nil {
		r.SetError(err)
		return
	}
	r.SetTLSInfo(tlsConn, elapsed(tt))

	trustedChains, err := verify(conf, tlsConn)
	if err != nil {
		r.SetError(err)
		return
	}

	tt = time.Now()
	readBuf, err := tlsRoundTrip(conf, tlsConn)
	if err != nil {
		r.SetError(err)
		return
	}
	recvStr := string(readBuf)
	r.SetTLSRoundTripInfo(recvStr, elapsed(tt))

	r.SetTrustedChains(trustedChains)
	return
}

func connect(conf *Config) (net.Conn, error) {
	errPrefix := "Network error."
	rawConn, err := net.DialTimeout(
		conf.DialNetwork(),
		fmt.Sprintf("%s:%d", *conf.Connect.Address, *conf.Connect.Port),
		conf.ConnectTimeout(),
	)
	if err != nil {
		return nil, fmt.Errorf("%s %s", errPrefix, err.Error())
	}

	return rawConn, nil
}

func plainRoundTrip(conf *Config, conn *net.TCPConn) (string, error) {
	errPrefix := "Roundtrip(plain data) error."
	writeBuf := conf.PlainData()
	if _, err := conn.Write(writeBuf); err != nil {
		return "", fmt.Errorf("%s Failed to write. %s", errPrefix, err.Error())
	}

	// discard plain data
	// XXX read size is hardcoded for now
	readBuf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(conf.PlainReadTimeout()))
	n, err := conn.Read(readBuf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok {
			if !netErr.Timeout() {
				return "", fmt.Errorf("%s Failed to read. %s", errPrefix, err.Error())
			}
		}
	}

	return string(readBuf[:n]), nil
}

func startTLS(conf *Config, conn net.Conn) (*tls.Conn, error) {
	errPrefix := "TLS error."
	tlsConn := tls.Client(conn, conf.TLSConfig())
	tlsConn.SetReadDeadline(time.Now().Add(conf.TLSReadTimeout()))
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("%s %s", errPrefix, err.Error())
	}
	return tlsConn, nil
}

func getPublicKeySize(pub interface{}) (sie int, err error) {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen(), nil
	case *ecdsa.PublicKey:
		return pub.Curve.Params().BitSize, nil
	}
	return 0, errors.New("only RSA and ECDSA public keys supported")

}

func verify(conf *Config, tlsConn *tls.Conn) ([][]*x509.Certificate, error) {
	errPrefix := "TLS verify error."

	connState := tlsConn.ConnectionState()
	serverCert := connState.PeerCertificates[0]

	roots := x509.NewCertPool()
	rootAdded := false
	for _, c := range conf.RootCerts() {
		roots.AddCert(c)
		rootAdded = true
	}
	if !conf.CheckTrustedByRoot() {
		i := len(connState.PeerCertificates) - 1
		roots.AddCert(connState.PeerCertificates[i])
		rootAdded = true
	}
	if !rootAdded {
		roots = nil
	}
	intermediates := x509.NewCertPool()
	for _, c := range connState.PeerCertificates[1:] {
		intermediates.AddCert(c)
	}

	verifyOpts := x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
	}

	serverName := conf.ServerNameForVerify()
	if serverName != nil {
		verifyOpts.DNSName = *serverName
	}

	chains, err := serverCert.Verify(verifyOpts)
	if err != nil {
		return nil, fmt.Errorf("%s %s", errPrefix, err.Error())
	}

	trustedChains := [][]*x509.Certificate{}
	revokeChains := make([]bool, len(chains))
	for i, chain := range chains {
		if conf.CheckRevocation() {
			revokeChains[i] = isRevokedChain(chain)
		} else {
			revokeChains[i] = false
		}
	}

	for i, b := range revokeChains {
		if !b {
			// valid chain found
			invalid := false
			for _, cert := range chains[i] {
				if !conf.CheckNotAfterRemains().Before(cert.NotAfter) {
					invalid = true
				}
				if _, ok := cert.PublicKey.(*rsa.PublicKey); ok {
					keylen, _ := getPublicKeySize(cert.PublicKey)
					if keylen <= conf.CheckMinRSABitlen() {
						invalid = true
					}
				}
				for _, sigAlgo := range conf.SignatureAlgorithmBlacklist() {
					if cert.SignatureAlgorithm == sigAlgo {
						invalid = true
					}
				}
			}
			if !invalid {
				trustedChains = append(trustedChains, chains[i])
			}
		}
	}

	if len(trustedChains) == 0 {
		return nil, fmt.Errorf("%s %s", errPrefix, "invalid certificate")
	}

	return trustedChains, nil
}

func tlsRoundTrip(conf *Config, tlsConn *tls.Conn) ([]byte, error) {
	errPrefix := "Application protocol error."
	writeBuf := conf.TLSData()
	if writeBuf != nil {
		tlsConn.Write(writeBuf)
	}

	readBuf := make([]byte, conf.TLSRecvSize())
	totalRead := 0
	for {
		tlsConn.SetReadDeadline(time.Now().Add(conf.TLSReadTimeout()))
		n, err := tlsConn.Read(readBuf[totalRead:])
		totalRead += n
		if totalRead >= conf.TLSRecvSize() {
			break
		}
		if err != nil {
			if err == io.EOF {
				return readBuf[0:totalRead], nil
			}
			if netErr, ok := err.(net.Error); ok {
				if netErr.Timeout() {
					return readBuf[0:totalRead], nil
				}
				return nil, fmt.Errorf("%s %s", errPrefix, err.Error())
			}
		}
	}
	return readBuf[0:totalRead], nil
}
