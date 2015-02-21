package tlschk

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"time"
)

// DoCheck starts tls check
func DoCheck(reader io.Reader) *Result {
	conf, err := LoadConfig(reader)
	if err != nil {
		return NewResult(err, nil)
	}

	rawConn, err := connect(conf)
	if err != nil {
		return NewResult(err, nil)
	}
	defer rawConn.Close()

	tlsConn, err := startTLS(conf, rawConn)
	if err != nil {
		return NewResult(err, nil)
	}

	if err := verify(conf, tlsConn); err != nil {
		return NewResult(err, tlsConn)
	}

	readBuf, err := roundTrip(conf, tlsConn)
	if err != nil {
		return NewResult(err, tlsConn)
	}
	recvStr := string(readBuf)

	result := NewResult(nil, tlsConn)
	result.Recv = &recvStr
	return result
}

func connect(conf *Config) (net.Conn, error) {
	errPrefix := "Network error."
	rawConn, err := net.DialTimeout(
		"tcp",
		fmt.Sprintf("%s:%d", *conf.Address, *conf.Port),
		conf.ConnectTimeout(),
	)
	if err != nil {
		return nil, fmt.Errorf("%s %s", errPrefix, err.Error())
	}

	tcpConn := rawConn.(*net.TCPConn)

	writeBuf := conf.PlainData()
	if writeBuf != nil {
		if _, err := rawConn.Write(writeBuf); err != nil {
			return nil, fmt.Errorf("%s Failed to write. %s", errPrefix, err.Error())
		}

		// discard plain data
		// XXX read size is hardcoded for now
		readBuf := make([]byte, 1024)
		tcpConn.SetReadDeadline(time.Now().Add(conf.ReadTimeout()))
		_, err = rawConn.Read(readBuf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok {
				if !netErr.Timeout() {
					return nil, fmt.Errorf("%s Failed to read. %s", errPrefix, err.Error())
				}
			}
		}

	}
	return rawConn, nil
}

func startTLS(conf *Config, conn net.Conn) (*tls.Conn, error) {
	errPrefix := "TLS error."
	tlsConn := tls.Client(conn, conf.TLSConfig())
	tlsConn.SetReadDeadline(time.Now().Add(conf.ReadTimeout()))
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("%s %s", errPrefix, err.Error())
	}
	return tlsConn, nil
}

func verify(conf *Config, tlsConn *tls.Conn) error {
	errPrefix := "TLS verify error."

	connState := tlsConn.ConnectionState()
	serverCert := connState.PeerCertificates[0]

	roots := x509.NewCertPool()
	rootAdded := false
	for _, c := range conf.RootCerts() {
		roots.AddCert(c)
		rootAdded = true
	}
	if !conf.CheckTrusted() {
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

	if _, err := serverCert.Verify(verifyOpts); err != nil {
		return fmt.Errorf("%s %s", errPrefix, err.Error())
	}

	// TODO revocation check
	return nil
}

func roundTrip(conf *Config, tlsConn *tls.Conn) ([]byte, error) {
	errPrefix := "Application protocol error."
	writeBuf := conf.TLSData()
	if writeBuf != nil {
		tlsConn.Write(writeBuf)
	}

	readBuf := make([]byte, conf.RecvSize())
	totalRead := 0
	for {
		tlsConn.SetReadDeadline(time.Now().Add(conf.ReadTimeout()))
		n, err := tlsConn.Read(readBuf[totalRead:])
		totalRead += n
		if totalRead >= conf.RecvSize() {
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
