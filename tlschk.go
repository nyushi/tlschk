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

func checkTimeout(c *Config, t time.Time) error {
	if c.Timeout == nil {
		return nil
	}
	if *c.Timeout == 0 {
		return nil
	}
	e := time.Now().Sub(t).Seconds()
	if e >= *c.Timeout {
		return errors.New("time exceeded")
	}
	return nil
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
	var el float64
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
	conf.UpdateTimeout(t)
	rawConn, err := connect(conf)
	if err != nil {
		r.SetError(err)
		return r
	}
	defer rawConn.Close()
	tcpConn := rawConn.(*net.TCPConn)
	el = elapsed(tt)
	if err := checkTimeout(conf, t); err != nil {
		r.SetError(err)
		return r
	}
	r.SetConnectionInfo(tcpConn, el)

	if conf.NeedPlainRoundTrip() {
		conf.UpdateTimeout(t)
		tt = time.Now()
		plainData, err := plainRoundTrip(conf, tcpConn)
		if err != nil {
			r.SetError(err)
			return r
		}
		el = elapsed(tt)
		if err := checkTimeout(conf, t); err != nil {
			r.SetError(err)
			return r
		}
		r.SetPlainRoundTripInfo(plainData, el)
	}

	tt = time.Now()
	tlsConn, err := startTLS(conf, rawConn)
	if err != nil {
		r.SetError(err)
		return r
	}
	el = elapsed(tt)
	if err := checkTimeout(conf, t); err != nil {
		r.SetError(err)
		return r
	}
	r.SetTLSInfo(tlsConn, el)

	trustedChains, invalidChains, err := verify(conf, tlsConn)
	if err != nil {
		r.SetError(err)
		return r
	}
	r.UpdateTLSInfo(invalidChains)

	if conf.NeedTLSRoundTrip() {
		conf.UpdateTimeout(t)
		tt = time.Now()
		readBuf, err := tlsRoundTrip(conf, tlsConn)
		if err != nil {
			r.SetError(err)
			return r
		}
		readStr := string(readBuf)
		el = elapsed(tt)
		if err := checkTimeout(conf, t); err != nil {
			r.SetError(err)
			return r
		}
		r.SetTLSRoundTripInfo(readStr, el)
	}
	r.SetTrustedChains(trustedChains)
	return r
}

func connect(conf *Config) (net.Conn, error) {
	errPrefix := "Network error."
	rawConn, err := net.DialTimeout(
		conf.DialNetwork(),
		conf.DialAddress(),
		conf.ConnectTimeout(),
	)
	if err != nil {
		return nil, fmt.Errorf("%s %s", errPrefix, err.Error())
	}

	return rawConn, nil
}

func plainRoundTrip(conf *Config, conn *net.TCPConn) (string, error) {
	errPrefix := "Roundtrip(plain data) error."
	buf, err := roundTrip(conn, conf.PlainData(), conf.PlainTimeout(), conf.PlainReadSize(), conf.PlainReadUntil())
	if err != nil {
		err = fmt.Errorf("%s Failed to read. %s", errPrefix, err.Error())
	}
	return string(buf), err
}

func startTLS(conf *Config, conn net.Conn) (*tls.Conn, error) {
	errPrefix := "TLS error."
	tlsConn := tls.Client(conn, conf.TLSConfig())
	tlsConn.SetDeadline(time.Now().Add(conf.HandshakeTimeout()))
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

func verify(conf *Config, tlsConn *tls.Conn) ([][]*Cert, [][]*Cert, error) {
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

	x509chains, err := serverCert.Verify(verifyOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("%s %s", errPrefix, err.Error())
	}

	trustedChains := [][]*Cert{}
	invalidChains := [][]*Cert{}
	for _, x509chain := range x509chains {
		chain := NewCertChain(x509chain)
		if conf.CheckRevocation() {
			chain.CheckRevocation()
		}
		valid := true
		if chain.IsRevoked() {
			valid = false
		}
		for _, cert := range chain {
			if !conf.CheckNotAfterRemains().Before(cert.NotAfter) {
				cert.Error += "nearing expiration. "
				valid = false
			}
			if _, ok := cert.PublicKey.(*rsa.PublicKey); ok {
				keylen, _ := getPublicKeySize(cert.PublicKey)
				if keylen <= conf.CheckMinRSABitlen() {
					cert.Error += "pubkey bitlen is short. "
					valid = false
				}
			}
			for _, sigAlgo := range conf.SignatureAlgorithmBlacklist() {
				if cert.SignatureAlgorithm == sigAlgo {
					cert.Error += "signature algorithm is obsoleted. "
					valid = false
				}
			}
		}

		if valid {
			trustedChains = append(trustedChains, chain)
		} else {
			invalidChains = append(invalidChains, chain)
		}
	}
	return trustedChains, invalidChains, nil
}

func tlsRoundTrip(conf *Config, tlsConn *tls.Conn) ([]byte, error) {
	errPrefix := "Application protocol error."
	buf, err := roundTrip(tlsConn, conf.TLSData(), conf.TLSTimeout(), conf.TLSReadSize(), conf.TLSReadUntil())
	if err != nil {
		err = fmt.Errorf("%s Failed to read. %s", errPrefix, err.Error())
	}
	return buf, err
}

func roundTrip(conn net.Conn, data []byte, timeout time.Duration, readSize int, readUntil []byte) ([]byte, error) {
	t := time.Now()
	if err := write(conn, timeout, data); err != nil {
		return nil, err
	}
	timeout = timeout - time.Now().Sub(t)
	return read(conn, timeout, readSize, readUntil)
}

func write(conn net.Conn, timeout time.Duration, data []byte) error {
	if data == nil {
		return nil
	}
	t := time.Now()
	wrote := 0
	for wrote < len(data) {
		el := time.Now().Sub(t)
		to := timeout - el
		conn.SetWriteDeadline(time.Now().Add(to))
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
	t := time.Now()
	for {
		el := time.Now().Sub(t)
		to := timeout - el
		conn.SetReadDeadline(time.Now().Add(to))
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
