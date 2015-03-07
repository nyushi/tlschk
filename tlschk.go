package tlschk

import (
	"bytes"
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
func DoCheck(reader io.Reader) *Result {
	r := &Result{Result: "OK"}
	conf, err := LoadConfig(reader)
	if err != nil {
		r.SetError(err)
		return r
	}
	return DoCheckByConfig(conf)
}

// DoCheckByConfig starts tls check
func DoCheckByConfig(conf *Config) *Result {
	r := &Result{Result: "OK"}

	t := time.Now()
	defer func() {
		r.Elapsed = elapsed(t)
	}()

	err := conf.Check()
	if err != nil {
		r.SetError(err)
		return r
	}

	var tt time.Time
	tt = time.Now()
	rawConn, err := connect(conf)
	if err != nil {
		r.SetError(err)
		return r
	}
	defer rawConn.Close()
	tcpConn := rawConn.(*net.TCPConn)
	r.SetConnectionInfo(tcpConn, elapsed(tt))

	if conf.NeedPlainRoundTrip() {
		tt = time.Now()
		plainData, err := plainRoundTrip(conf, tcpConn)
		if err != nil {
			r.SetError(err)
			return r
		}
		r.SetPlainRoundTripInfo(plainData, elapsed(tt))
	}

	tt = time.Now()
	tlsConn, err := startTLS(conf, rawConn)
	if err != nil {
		r.SetError(err)
		return r
	}
	r.SetTLSInfo(tlsConn, elapsed(tt))

	trustedChains, err := verify(conf, tlsConn)
	if err != nil {
		r.SetError(err)
		return r
	}

	if conf.NeedTLSRoundTrip() {
		tt = time.Now()
		readBuf, err := tlsRoundTrip(conf, tlsConn)
		if err != nil {
			r.SetError(err)
			return r
		}
		readStr := string(readBuf)
		r.SetTLSRoundTripInfo(readStr, elapsed(tt))
	}
	r.SetTrustedChains(trustedChains)
	return r
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
	buf, err := roundTrip(conn, conf.PlainData(), conf.PlainReadTimeout(), conf.PlainReadSize(), conf.PlainReadUntil())
	if err != nil {
		err = fmt.Errorf("%s Failed to read. %s", errPrefix, err.Error())
	}
	return string(buf), err
}

func startTLS(conf *Config, conn net.Conn) (*tls.Conn, error) {
	errPrefix := "TLS error."
	tlsConn := tls.Client(conn, conf.TLSConfig())
	tlsConn.SetDeadline(time.Now().Add(defaultHandshakeTimeout))
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
	buf, err := roundTrip(tlsConn, conf.TLSData(), conf.TLSReadTimeout(), conf.TLSReadSize(), conf.TLSReadUntil())
	if err != nil {
		err = fmt.Errorf("%s Failed to read. %s", errPrefix, err.Error())
	}
	return buf, err
}

func roundTrip(conn net.Conn, data []byte, timeout time.Duration, readSize int, readUntil []byte) ([]byte, error) {
	if err := write(conn, timeout, data); err != nil {
		return nil, err
	}
	return read(conn, timeout, readSize, readUntil)
}

func write(conn net.Conn, timeout time.Duration, data []byte) error {
	if data == nil {
		return nil
	}
	wrote := 0
	for wrote < len(data) {
		conn.SetWriteDeadline(time.Now().Add(timeout))
		n, err := conn.Write(data[wrote:])
		if err != nil {
			if nerr, ok := err.(net.Error); ok {
				if nerr.Temporary() {
					continue
				}
			}
			return err
		}
		wrote += n
	}
	return nil
}

func read(conn net.Conn, timeout time.Duration, size int, until []byte) ([]byte, error) {
	buf := make([]byte, size)
	totalRead := 0
	for {
		conn.SetReadDeadline(time.Now().Add(timeout))
		n, err := conn.Read(buf[totalRead:])
		if err != nil {
			if err == io.EOF {
				return buf[0:totalRead], nil
			}
			if nerr, ok := err.(net.Error); ok {
				if nerr.Timeout() {
					break
				}
				return nil, err
			}
		}
		totalRead += n
		if bytes.Contains(buf[0:totalRead], until) {
			break
		}
		if totalRead >= size {
			break
		}
	}
	return buf[0:totalRead], nil
}
