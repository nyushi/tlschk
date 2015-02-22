package tlschk

import (
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type errReader struct {
	msg string
}

func (e errReader) Read([]byte) (int, error) {
	return 0, errors.New(e.msg)
}

func TestLoadConfigRequired(t *testing.T) {
	tests := []struct {
		in  io.Reader
		out error
	}{
		{
			errReader{"this is error"},
			errors.New("Config error. Failed to read input. this is error"),
		},
		{
			strings.NewReader(``),
			errors.New("Config error. Failed to load config json. unexpected end of JSON input"),
		},
		{
			strings.NewReader(`{"address": "127.0.0.1"}`),
			errors.New("Config error. port is required"),
		},
		{
			strings.NewReader(`{"port": 443}`),
			errors.New("Config error. address is required"),
		},
		{
			strings.NewReader(`{"address": "127.0.0.1", "port": 443, "connection": {"ip_version": 0}}`),
			errors.New("Config error. ip_version allows 4 or 6"),
		},
		{
			strings.NewReader(`{"address": "127.0.0.1", "port": 443, "connection": {"ip_version": 4}}`),
			nil,
		},
		{
			strings.NewReader(`{"address": "127.0.0.1", "port": 443, "connection": {"ip_version": 6}}`),
			nil,
		},
	}

	for _, test := range tests {
		_, err := LoadConfig(test.in)
		if err == nil && test.out == nil {
		} else if err != nil && test.out == nil {
			t.Errorf("LoadConfigs returns %q, want nil", err.Error())
		} else if err == nil && test.out != nil {
			t.Errorf("LoadConfigs returns nil, want %q", test.out.Error())
		} else if err.Error() != test.out.Error() {
			t.Errorf("LoadConfigs returns %q, want %q", err.Error(), test.out.Error())
		}
	}

	c, err := LoadConfig(strings.NewReader(`{"address": "127.0.0.1", "port": 443}`))
	if err != nil {
		t.Errorf("LoadConfig returns error %q", err)
	}
	if *c.Address != "127.0.0.1" {
		t.Errorf("LoadConfig loaded address is %q, want 127.0.0.1", *c.Address)
	}
	if *c.Port != 443 {
		t.Errorf("LoadConfig loaded port is %q, want 127.0.0.1", *c.Port)
	}
}

func TestCheck(t *testing.T) {
	addr := "127.0.0.1"
	port := 443
	v := verifyOptions{
		RootCerts: []string{""},
	}
	c := Config{
		Address: &addr,
		Port:    &port,
		Verify:  &v,
	}

	b := &pem.Block{Type: "CERTIFICATE", Bytes: []byte("abc")}
	invalidCertPEM := &bytes.Buffer{}
	pem.Encode(invalidCertPEM, b)

	var err error
	var prefix string
	for _, pemStr := range []string{"", string(root.KeyPEM), invalidCertPEM.String()} {
		c.Verify.RootCerts = []string{pemStr}
		err = c.Check()
		if err == nil {
			t.Fatal("Config.Check not returns error")
		}
		prefix = "root_certs[0]:"
		if !strings.HasPrefix(err.Error(), prefix) {
			t.Errorf("Config.Check returns %q, not starts with %q", err.Error(), prefix)
		}
	}
}

func TestTLSConfig(t *testing.T) {
	c := Config{}
	tlsc := c.TLSConfig()
	if !tlsc.InsecureSkipVerify {
		t.Error("InsecureSkipVerify is true")
	}
}

func TestServerNameForVerify(t *testing.T) {
	c := Config{}
	v := c.ServerNameForVerify()
	if v != nil {
		t.Errorf("Config.ServerNameForVerify is %q, want nil", v)
	}

	c.Verify = &verifyOptions{}
	v = c.ServerNameForVerify()
	if v != nil {
		t.Errorf("Config.ServerNameForVerify is %q, want nil", v)
	}

	n := "name"
	c.Verify.CheckServername = &n
	v = c.ServerNameForVerify()
	if *v != n {
		t.Errorf("Config.ServerNameForVerify is %q, want %q", *v, n)
	}
}

func TestDialNetwork(t *testing.T) {
	c := Config{}
	var want string
	tcp := "tcp"
	tcp4 := "tcp4"
	tcp6 := "tcp6"

	want = tcp
	v := c.DialNetwork()
	if v != want {
		t.Errorf("Config.DialNetwork is %q, want %q", v, want)
	}

	c.Connection = &connectionOptions{}
	v = c.DialNetwork()
	if v != want {
		t.Errorf("Config.DialNetwork is %q, want %q", v, want)
	}

	var ver int64
	ver = 4
	want = tcp4
	c.Connection.IPVersion = &ver
	v = c.DialNetwork()
	if v != want {
		t.Errorf("Config.DialNetwork is %q, want %q", v, want)
	}

	ver = 6
	want = tcp6
	c.Connection.IPVersion = &ver
	v = c.DialNetwork()
	if v != want {
		t.Errorf("Config.DialNetwork is %q, want %q", v, want)
	}

	ver = 7
	want = tcp
	c.Connection.IPVersion = &ver
	v = c.DialNetwork()
	if v != tcp {
		t.Errorf("Config.DialNetwork is %q, want %q", v, want)
	}
}

func TestConnectTimeout(t *testing.T) {
	c := Config{}
	to := time.Second * 10

	v := c.ConnectTimeout()
	if v != to {
		t.Errorf("Config.ConnectTimeout is %q, want %q", v, to)
	}

	c.Connection = &connectionOptions{}
	v = c.ConnectTimeout()
	if v != to {
		t.Errorf("Config.ConnectTimeout is %q, want %q", v, to)
	}

	var tt int64 = 1
	c.Connection.ConnectTimeout = &tt
	v = c.ConnectTimeout()
	d := time.Duration(tt) * time.Second
	if v != d {
		t.Errorf("Config.ConnectTimeout is %q, want %q", v, d)
	}
}

func TestReadTimeout(t *testing.T) {
	c := Config{}
	to := time.Second * 10

	v := c.ReadTimeout()
	if v != to {
		t.Errorf("Config.ReadTimeout is %q, want %q", v, to)
	}

	c.Connection = &connectionOptions{}
	v = c.ReadTimeout()
	if v != to {
		t.Errorf("Config.ReadTimeout is %q, want %q", v, to)
	}

	var tt int64 = 1
	c.Connection.ReadTimeout = &tt
	v = c.ReadTimeout()
	d := time.Duration(tt) * time.Second
	if v != d {
		t.Errorf("Config.ReadTimeout is %q, want %q", v, d)

	}
}

func TestPlainData(t *testing.T) {
	c := Config{}

	v := c.PlainData()
	if v != nil {
		t.Errorf("Config.PlainData is %q, want nil", v)
	}

	c.Connection = &connectionOptions{}
	v = c.PlainData()
	if v != nil {
		t.Errorf("Config.PlainData is %q, want nil", v)
	}

	d := "data"
	c.Connection.SendPlain = &d
	v = c.PlainData()
	if string(v) != d {
		t.Errorf("Config.PlainData is %q, want %q", v, d)

	}
}

func TestTLSData(t *testing.T) {
	c := Config{}

	v := c.TLSData()
	if v != nil {
		t.Errorf("Config.TLSData is %q, want nil", v)
	}

	c.Connection = &connectionOptions{}
	v = c.TLSData()
	if v != nil {
		t.Errorf("Config.TLSData is %q, want nil", v)
	}

	d := "data"
	c.Connection.SendTLS = &d
	v = c.TLSData()
	if string(v) != d {
		t.Errorf("Config.TLSData is %q, want %q", v, d)

	}
}

func TestRecvSize(t *testing.T) {
	c := Config{}
	v := c.RecvSize()
	if v != 1024 {
		t.Errorf("Config.RecvSize is %q, want 1024", v)
	}

	c.Connection = &connectionOptions{}
	v = c.RecvSize()
	if v != 1024 {
		t.Errorf("Config.RecvSize is %q, want 1024", v)
	}

	rs := 1
	c.Connection.RecvSize = &rs
	v = c.RecvSize()
	if v != rs {
		t.Errorf("Config.RecvSize is %q, want %q", v, rs)
	}
}

func TestCheckTrusted(t *testing.T) {
	c := Config{}
	v := c.CheckTrusted()
	if !v {
		t.Errorf("Config.CheckTrusted is %q, want true", v)
	}

	c.Verify = &verifyOptions{}
	v = c.CheckTrusted()
	if !v {
		t.Errorf("Config.CheckTrusted is %q, want true", v)
	}

	f := false
	c.Verify.CheckTrusted = &f
	v = c.CheckTrusted()
	if v {
		t.Errorf("Config.CheckTrusted is %v, want %v", v, f)
	}
}

func TestRootCerts(t *testing.T) {
	c := Config{}
	v := c.RootCerts()
	if v != nil {
		t.Errorf("Config.RootCerts is %q, want nil", v)
	}

	c.Verify = &verifyOptions{}
	v = c.RootCerts()
	if v != nil {
		t.Errorf("Config.RootCerts is %q, want nil", v)
	}

	c.Verify.RootCerts = []string{string(root.CertPEM)}
	v = c.RootCerts()
	if len(v) != 1 {
		t.Errorf("Config.RootCerts size is %q, want 1", len(v))
	}
}

func TestCipherSuites(t *testing.T) {
	c := Config{}

	var v []uint16
	var errs []error
	v, errs = c.CipherSuites()
	if v != nil {
		t.Errorf("Config.CipherSuites returns %q, not nil", v)
	}
	if errs != nil {
		t.Errorf("Config.CipherSuites returns %q, not nil", errs)
	}

	c.Handshake = &handshakeOptions{}
	v, errs = c.CipherSuites()
	if v != nil {
		t.Errorf("Config.CipherSuites returns %q, not nil", v)
	}
	if errs != nil {
		t.Errorf("Config.CipherSuites returns %q, not nil", errs)
	}

	c.Handshake.CipherSuites = []string{"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "no such cipher"}
	v, errs = c.CipherSuites()
	if v == nil {
		t.Error("Config.CipherSuites returns nil")
	}
	if len(v) != 1 {
		t.Errorf("Config.CipherSuites returns size %q slice, want 1", len(v))
	}
	if errs == nil {
		t.Error("Config.CipherSuites returns nil")
	}
	if len(errs) != 1 {
		t.Errorf("Config.CipherSuites returns size %q slice, want 1", len(errs))
	}
}

func TestMinVersion(t *testing.T) {
	c := Config{}
	var v uint16
	var err error

	v, err = c.MinVersion()
	if v != 0 {
		t.Errorf("Config.MinVersion returns %q, want 0", v)
	}
	if err != nil {
		t.Errorf("Config.MinVersion returns %q, want nil", err.Error())
	}

	c.Handshake = &handshakeOptions{}
	v, err = c.MinVersion()
	if v != 0 {
		t.Errorf("Config.MinVersion returns %q, want 0", v)
	}
	if err != nil {
		t.Errorf("Config.MinVersion returns %q, want nil", err.Error())
	}

	versionStr := "TLS1.2"
	c.Handshake.MinVersion = &versionStr
	v, err = c.MinVersion()
	if v != tls.VersionTLS12 {
		t.Errorf("Config.MinVersion returns %q, want %q", v, tls.VersionTLS12)
	}
	if err != nil {
		t.Errorf("Config.MinVersion returns %q, want nil", err.Error())
	}

	versionStr = "no such version"
	c.Handshake.MinVersion = &versionStr
	v, err = c.MinVersion()
	if v != 0 {
		t.Errorf("Config.MinVersion returns %q, want 0", v)
	}
	if err == nil {
		t.Errorf("Config.MinVersion returns nil, want error")
	}
}

func TestMaxVersion(t *testing.T) {
	c := Config{}
	var v uint16
	var err error

	v, err = c.MaxVersion()
	if v != 0 {
		t.Errorf("Config.MaxVersion returns %q, want 0", v)
	}
	if err != nil {
		t.Errorf("Config.MaxVersion returns %q, want nil", err.Error())
	}

	c.Handshake = &handshakeOptions{}
	v, err = c.MaxVersion()
	if v != 0 {
		t.Errorf("Config.MaxVersion returns %q, want 0", v)
	}
	if err != nil {
		t.Errorf("Config.MaxVersion returns %q, want nil", err.Error())
	}

	versionStr := "TLS1.2"
	c.Handshake.MaxVersion = &versionStr
	v, err = c.MaxVersion()
	if v != tls.VersionTLS12 {
		t.Errorf("Config.MaxVersion returns %q, want %q", v, tls.VersionTLS12)
	}
	if err != nil {
		t.Errorf("Config.MaxVersion returns %q, want nil", err.Error())
	}

	versionStr = "no such version"
	c.Handshake.MaxVersion = &versionStr
	v, err = c.MaxVersion()
	if v != 0 {
		t.Errorf("Config.MaxVersion returns %q, want 0", v)
	}
	if err == nil {
		t.Errorf("Config.MaxVersion returns nil, want error")
	}
}
