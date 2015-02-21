package tlschk

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

var root, chain, leaf *certData

func init() {
	root = getCert("root", true, nil)
	chain = getCert("chain", true, root)
	leaf = getCert("localhost", false, chain)
}

type certData struct {
	CertDER  []byte
	CertPEM  []byte
	KeyPEM   []byte
	Key      *rsa.PrivateKey
	TLSCert  *tls.Certificate
	X509Cert *x509.Certificate
}

func getCert(commonName string, isCA bool, parentData *certData) *certData {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	notBefore := time.Now()
	notAfter := time.Now().Add(time.Hour)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"tlschk test"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	parent := &template
	parentKey := priv
	if parentData != nil {
		parent = parentData.X509Cert
		parentKey = parentData.Key
	}
	derBytes, _ := x509.CreateCertificate(rand.Reader, &template, parent, &priv.PublicKey, parentKey)

	certPEM := &bytes.Buffer{}
	keyPEM := &bytes.Buffer{}
	pem.Encode(certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	pem.Encode(keyPEM, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	tlscert, _ := tls.X509KeyPair(certPEM.Bytes(), keyPEM.Bytes())
	x509cert, _ := x509.ParseCertificate(derBytes)

	return &certData{
		CertDER:  derBytes,
		CertPEM:  certPEM.Bytes(),
		KeyPEM:   keyPEM.Bytes(),
		Key:      priv,
		TLSCert:  &tlscert,
		X509Cert: x509cert,
	}
}

func runServer(listened chan struct{}, chain, leaf *certData, f func(net.Conn, *tls.Conn)) {
	combinedCerts := leaf.CertPEM
	combinedCerts = append(combinedCerts, chain.CertPEM...)
	combined, _ := tls.X509KeyPair(combinedCerts, leaf.KeyPEM)
	config := tls.Config{
		ServerName: "localhost",
		Certificates: []tls.Certificate{
			combined,
		},
	}
	listener, err := net.Listen("tcp", "127.0.0.1:4443")
	if err != nil {
		log.Println(err)
	}
	defer listener.Close()

	listened <- struct{}{}

	conn, _ := listener.Accept()
	tlsConn := tls.Server(conn, &config)
	defer conn.Close()
	f(conn, tlsConn)
}

func TestDoCheckConfigError(t *testing.T) {
	r := strings.NewReader(``)
	result := DoCheck(r)
	if result.Result != "NG" {
		t.Error("result is not NG")
	}
	prefix := "Config error."
	if !strings.HasPrefix(result.Detail, prefix) {
		t.Fatalf("detail is %q, not starts with %q", result.Detail, prefix)
	}
	if result.Recv != nil {
		t.Fatalf("recv is %q, want nil", *result.Recv)
	}
}

func TestDoCheckRefused(t *testing.T) {
	r := strings.NewReader(`
{
  "address": "127.0.0.1",
  "port": 4443,
  "verify": {
    "check_trusted": false
  },
  "connection": {
    "read_timeout": 1,
    "connect_timeout": 1
  }
}`)
	result := DoCheck(r)
	if result.Result != "NG" {
		t.Error("result is not NG")
	}
	prefix := "Network error."
	if !strings.HasPrefix(result.Detail, prefix) {
		t.Fatalf("detail is %q, not starts with %q", result.Detail, prefix)
	}
	if result.Recv != nil {
		t.Fatalf("recv is %q, want nil", *result.Recv)
	}
}

func TestDoCheckSuccess(t *testing.T) {
	listened := make(chan struct{}, 1)
	f := func(conn net.Conn, tlsConn *tls.Conn) {
		tlsConn.Handshake()
	}
	go runServer(listened, chain, leaf, f)

	<-listened

	r := strings.NewReader(`
{
  "address": "127.0.0.1",
  "port": 4443,
  "verify": {
    "check_trusted": false
  },
  "connection": {
    "read_timeout": 1,
    "connect_timeout": 1
  }
}`)
	result := DoCheck(r)
	if result.Result != "OK" {
		t.Error("result is not OK")
	}
	if result.Detail != "" {
		t.Fatalf("detail is %q, want \"\"", result.Detail)
	}
	if result.Recv == nil {
		t.Fatal("recv is nil")
	}
	if *result.Recv != "" {
		t.Fatalf("recv is %q, want \"\"", *result.Recv)
	}
}

func TestDoCheckSuccessStartTLS(t *testing.T) {
	listened := make(chan struct{}, 1)
	f := func(conn net.Conn, tlsConn *tls.Conn) {
		readbuf := make([]byte, 512)
		n, _ := conn.Read(readbuf)
		if bytes.Equal(readbuf[:n], []byte("STARTTLS\r\n")) {
			tlsConn.Handshake()
		}
	}
	go runServer(listened, chain, leaf, f)

	<-listened

	r := strings.NewReader(`
{
  "address": "127.0.0.1",
  "port": 4443,
  "verify": {
    "check_trusted": false
  },
  "connection": {
    "read_timeout": 1,
    "connect_timeout": 1,
    "send_plain": "STARTTLS\r\n"
  }
}`)
	result := DoCheck(r)
	println(result.Detail)
	if result.Result != "OK" {
		t.Error("result is not OK")
	}
	if result.Detail != "" {
		t.Fatalf("detail is %q, want \"\"", result.Detail)
	}
	if result.Recv == nil {
		t.Fatal("recv is nil")
	}
	if *result.Recv != "" {
		t.Fatalf("recv is %q, want \"\"", *result.Recv)
	}
}

func TestDoCheckHandshakeFailed(t *testing.T) {
	listened := make(chan struct{}, 1)
	f := func(conn net.Conn, tlsConn *tls.Conn) {
		tlsConn.Close()
	}
	go runServer(listened, chain, leaf, f)

	<-listened

	r := strings.NewReader(`
{
  "address": "127.0.0.1",
  "port": 4443,
  "verify": {
    "check_trusted": false
  },
  "connection": {
    "read_timeout": 1,
    "connect_timeout": 1
  }
}`)
	result := DoCheck(r)
	if result.Result != "NG" {
		t.Error("result is not NG")
	}
	prefix := "TLS error."
	if !strings.HasPrefix(result.Detail, prefix) {
		t.Fatalf("detail is %q, not starts with %q", result.Detail, prefix)
	}
	if result.Recv != nil {
		t.Fatalf("recv is %q, want nil", *result.Recv)
	}
}

func TestDoCheckServerNameMatch(t *testing.T) {
	listened := make(chan struct{}, 1)
	f := func(conn net.Conn, tlsConn *tls.Conn) {
		tlsConn.Handshake()
	}
	go runServer(listened, chain, leaf, f)

	<-listened

	r := strings.NewReader(`
{
  "address": "127.0.0.1",
  "port": 4443,
  "verify": {
    "check_servername": "localhost",
    "check_trusted": false
  },
  "connection": {
    "read_timeout": 1,
    "connect_timeout": 1
  }
}`)
	result := DoCheck(r)
	if result.Result != "OK" {
		t.Error("result is not OK")
	}
	if result.Detail != "" {
		t.Fatalf("detail is %q, want \"\"", result.Detail)
	}
}

func TestDoCheckServerNameNotMatch(t *testing.T) {
	listened := make(chan struct{}, 1)
	f := func(conn net.Conn, tlsConn *tls.Conn) {
		tlsConn.Handshake()
	}
	go runServer(listened, chain, leaf, f)

	<-listened

	r := strings.NewReader(`
{
  "address": "127.0.0.1",
  "port": 4443,
  "verify": {
    "check_servername": "example.com",
    "check_trusted": false
  },
  "connection": {
    "read_timeout": 1,
    "connect_timeout": 1
  }
}`)
	result := DoCheck(r)
	if result.Result != "NG" {
		t.Error("result is not NG")
	}
	prefix := "TLS verify error."
	if !strings.HasPrefix(result.Detail, prefix) {
		t.Fatalf("detail is %q, not starts with %q", result.Detail, prefix)
	}
}

func TestDoCheckTrustedOK(t *testing.T) {
	listened := make(chan struct{}, 1)
	f := func(conn net.Conn, tlsConn *tls.Conn) {
		tlsConn.Handshake()
	}
	go runServer(listened, chain, leaf, f)

	<-listened

	j := fmt.Sprintf(`
{
  "address": "127.0.0.1",
  "port": 4443,
  "verify": {
    "check_trusted": true,
    "root_certs": [%q]
  },
  "connection": {
    "read_timeout": 1,
    "connect_timeout": 1
  }
}`, chain.CertPEM)
	r := strings.NewReader(j)

	result := DoCheck(r)
	if result.Result != "OK" {
		t.Error("result is not OK")
	}
	if result.Detail != "" {
		t.Fatalf("detail is %q, not \"\"", result.Detail)
	}
}

func TestDoCheckTrustedNG(t *testing.T) {
	listened := make(chan struct{}, 1)
	f := func(conn net.Conn, tlsConn *tls.Conn) {
		tlsConn.Handshake()
	}
	go runServer(listened, chain, leaf, f)

	<-listened

	r := strings.NewReader(`
{
  "address": "127.0.0.1",
  "port": 4443,
  "verify": {
    "check_trusted": true
  },
  "connection": {
    "read_timeout": 1,
    "connect_timeout": 1
  }
}`)

	result := DoCheck(r)
	if result.Result != "NG" {
		t.Error("result is not NG")
	}
	prefix := "TLS verify error."
	if !strings.HasPrefix(result.Detail, prefix) {
		t.Fatalf("detail is %q, not starts with %q", result.Detail, prefix)
	}
}

func TestDoCheckReadData(t *testing.T) {
	listened := make(chan struct{}, 1)
	f := func(conn net.Conn, tlsConn *tls.Conn) {
		tlsConn.Handshake()
		tlsConn.Write([]byte("testtest"))
	}
	go runServer(listened, chain, leaf, f)

	<-listened

	r := strings.NewReader(`
{
  "address": "127.0.0.1",
  "port": 4443,
  "verify": {
    "check_trusted": false
  },
  "connection": {
    "read_timeout": 1,
    "connect_timeout": 1,
    "recv_size": 4
  }
}`)

	result := DoCheck(r)
	if result.Result != "OK" {
		t.Error("result is not OK")
	}
	if result.Detail != "" {
		t.Fatalf("detail is %q, not \"\"", result.Detail)
	}
	if result.Recv == nil {
		t.Fatalf("recv is nil")
	}
	recv := "test"
	if *result.Recv != recv {
		t.Fatalf("detail is %q, not %q", result.Detail, recv)
	}
}

func TestDoCheckReadDataTimeout(t *testing.T) {
	syncer := make(chan struct{}, 1)
	listened := make(chan struct{}, 1)
	f := func(conn net.Conn, tlsConn *tls.Conn) {
		tlsConn.Handshake()
		tlsConn.Write([]byte("t"))
		<-syncer
	}
	go runServer(listened, chain, leaf, f)

	<-listened

	r := strings.NewReader(`
{
  "address": "127.0.0.1",
  "port": 4443,
  "verify": {
    "check_trusted": false
  },
  "connection": {
    "read_timeout": 1,
    "connect_timeout": 1,
    "recv_size": 4
  }
}`)

	result := DoCheck(r)
	syncer <- struct{}{}
	if result.Result != "OK" {
		t.Error("result is not OK")
	}
	if result.Detail != "" {
		t.Fatalf("detail is %q, not \"\"", result.Detail)
	}
	if result.Recv == nil {
		t.Fatalf("recv is nil")
	}
	recv := "t"
	if *result.Recv != recv {
		t.Fatalf("detail is %q, not %q", result.Detail, recv)
	}
}

func TestDoCheckInvalidChain(t *testing.T) {
	listened := make(chan struct{}, 1)
	f := func(conn net.Conn, tlsConn *tls.Conn) {
		tlsConn.Handshake()
	}
	go runServer(listened, root, leaf, f) // mismatch

	<-listened

	r := strings.NewReader(`
{
  "address": "127.0.0.1",
  "port": 4443,
  "verify": {
    "check_trusted": true
  },
  "connection": {
    "read_timeout": 1,
    "connect_timeout": 1
  }
}`)

	result := DoCheck(r)
	if result.Result != "NG" {
		t.Error("result is not NG")
	}
	prefix := "TLS verify error."
	if !strings.HasPrefix(result.Detail, prefix) {
		t.Fatalf("detail is %q, not starts with %q", result.Detail, prefix)
	}
}
