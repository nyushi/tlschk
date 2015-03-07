package tlschk

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
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
			strings.NewReader(`{}`),
			errors.New("Config error. connect is required"),
		},
		{
			strings.NewReader(`{"connect": {"address": "127.0.0.1"}}`),
			errors.New("Config error. port is required"),
		},
		{
			strings.NewReader(`{"connect": {"port": 443}}`),
			errors.New("Config error. address is required"),
		},
		{
			strings.NewReader(`{"connect": {"address": "127.0.0.1", "port": 443, "ip_version": 0}}`),
			errors.New("Config error. ip_version allows 4 or 6"),
		},
		{
			strings.NewReader(`{"connect": {"address": "127.0.0.1", "port": 443}, "handshake": {"cipher_suites": ["no_such_cipher1", "no_such_cipher2"]}}`),
			errors.New("Config error. no_such_cipher1 is not supported, no_such_cipher2 is not supported"),
		},
		{
			strings.NewReader(`{"connect": {"address": "127.0.0.1", "port": 443}, "handshake": {"min_version": "no_such_version"}}`),
			errors.New("Config error. no_such_version is not supported"),
		},
		{
			strings.NewReader(`{"connect": {"address": "127.0.0.1", "port": 443}, "handshake": {"max_version": "no_such_version"}}`),
			errors.New("Config error. no_such_version is not supported"),
		},
		{
			strings.NewReader(`{"connect": {"address": "127.0.0.1", "port": 443, "ip_version": 4}}`),
			nil,
		},
		{
			strings.NewReader(`{"connect":{"address": "127.0.0.1", "port": 443, "ip_version": 6}}`),
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

	c, err := LoadConfig(strings.NewReader(`{"connect": {"address": "127.0.0.1", "port": 443}}`))
	if err != nil {
		t.Errorf("LoadConfig returns error %q", err)
	}
	if *c.Connect.Address != "127.0.0.1" {
		t.Errorf("LoadConfig loaded address is %q, want 127.0.0.1", *c.Connect.Address)
	}
	if *c.Connect.Port != 443 {
		t.Errorf("LoadConfig loaded port is %q, want 127.0.0.1", *c.Connect.Port)
	}
}

func TestCheck(t *testing.T) {
	addr := "127.0.0.1"
	port := 443
	c := Config{
		Connect: &ConnectOptions{
			Address: &addr,
			Port:    &port,
		},
		Handshake: &HandshakeOptions{
			RootCerts: []string{""},
		},
	}

	b := &pem.Block{Type: "CERTIFICATE", Bytes: []byte("abc")}
	invalidCertPEM := &bytes.Buffer{}
	pem.Encode(invalidCertPEM, b)

	var err error
	var prefix string
	for _, pemStr := range []string{"", string(root.KeyPEM), invalidCertPEM.String()} {
		c.Handshake.RootCerts = []string{pemStr}
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

	c.Handshake = &HandshakeOptions{}
	v = c.ServerNameForVerify()
	if v != nil {
		t.Errorf("Config.ServerNameForVerify is %q, want nil", v)
	}

	n := "name"
	c.Handshake.CheckServername = &n
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

	c.Connect = &ConnectOptions{}
	v = c.DialNetwork()
	if v != want {
		t.Errorf("Config.DialNetwork is %q, want %q", v, want)
	}

	var ver int64
	ver = 4
	want = tcp4
	c.Connect.IPVersion = &ver
	v = c.DialNetwork()
	if v != want {
		t.Errorf("Config.DialNetwork is %q, want %q", v, want)
	}

	ver = 6
	want = tcp6
	c.Connect.IPVersion = &ver
	v = c.DialNetwork()
	if v != want {
		t.Errorf("Config.DialNetwork is %q, want %q", v, want)
	}

	ver = 7
	want = tcp
	c.Connect.IPVersion = &ver
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

	c.Connect = &ConnectOptions{}
	v = c.ConnectTimeout()
	if v != to {
		t.Errorf("Config.ConnectTimeout is %q, want %q", v, to)
	}

	var tt int64 = 1
	c.Connect.Timeout = &tt
	v = c.ConnectTimeout()
	d := time.Duration(tt) * time.Second
	if v != d {
		t.Errorf("Config.ConnectTimeout is %q, want %q", v, d)
	}
}

func TestPlainReadTimeout(t *testing.T) {
	c := Config{}

	v := c.PlainReadTimeout()
	if v != 0 {
		t.Errorf("Config.PlainReadTimeout is %q, want 0", v)
	}

	c.PlainRoundTrip = &RoundTripOptions{}
	v = c.PlainReadTimeout()
	if v != 0 {
		t.Errorf("Config.PlainReadTimeout is %q, want 0", v)
	}

	var tt int64 = 1
	c.PlainRoundTrip.ReadTimeout = &tt
	v = c.PlainReadTimeout()
	d := time.Duration(tt) * time.Second
	if v != d {
		t.Errorf("Config.PlainReadTimeout is %q, want %q", v, d)

	}
}

func TestTLSReadTimeout(t *testing.T) {
	c := Config{}

	v := c.TLSReadTimeout()
	if v != 0 {
		t.Errorf("Config.TLSReadTimeout is %q, want 0", v)
	}

	c.TLSRoundTrip = &RoundTripOptions{}
	v = c.TLSReadTimeout()
	if v != 0 {
		t.Errorf("Config.TLSReadTimeout is %q, want 0", v)
	}

	var tt int64 = 1
	c.TLSRoundTrip.ReadTimeout = &tt
	v = c.TLSReadTimeout()
	d := time.Duration(tt) * time.Second
	if v != d {
		t.Errorf("Config.TLSReadTimeout is %q, want %q", v, d)

	}
}

func TestPlainData(t *testing.T) {
	c := Config{}

	v := c.PlainData()
	if v != nil {
		t.Errorf("Config.PlainData is %q, want nil", v)
	}

	c.PlainRoundTrip = &RoundTripOptions{}
	v = c.PlainData()
	if v != nil {
		t.Errorf("Config.PlainData is %q, want nil", v)
	}

	d := "data"
	c.PlainRoundTrip.Send = &d
	v = c.PlainData()
	if string(v) != d {
		t.Errorf("Config.PlainData is %q, want %q", v, d)

	}
}

func TestPlainReadUntil(t *testing.T) {
	c := Config{}

	v := c.PlainReadUntil()
	if v != nil {
		t.Errorf("Config.PlainReadUntil is %q, want nil", v)
	}

	c.PlainRoundTrip = &RoundTripOptions{}
	v = c.PlainReadUntil()
	if v != nil {
		t.Errorf("Config.PlainReadUntil is %q, want nil", v)
	}

	d := "data"
	c.PlainRoundTrip.ReadUntil = &d
	v = c.PlainReadUntil()
	if string(v) != d {
		t.Errorf("Config.PlainReadUntil is %q, want %q", v, d)

	}
}

func TestNeedPlainRoundTrip(t *testing.T) {
	c := Config{}

	v := c.NeedPlainRoundTrip()
	if v != false {
		t.Errorf("Config.NeedPlainRoundTrip is %t, want false", v)
	}

	c.PlainRoundTrip = &RoundTripOptions{}
	v = c.NeedPlainRoundTrip()
	if v != false {
		t.Errorf("Config.NeedPlainRoundTrip is %t, want false", v)
	}

	d := ""
	c.PlainRoundTrip.Send = &d
	v = c.NeedPlainRoundTrip()
	if v != false {
		t.Errorf("Config.NeedPlainRoundTrip is %t, want false", v)
	}

	d = "data"
	c.PlainRoundTrip.Send = &d
	v = c.NeedPlainRoundTrip()
	if v != true {
		t.Errorf("Config.NeedPlainRoundTrip is %t, want true", v)
	}

	c.PlainRoundTrip.Send = nil
	var to int64 = 1
	c.PlainRoundTrip.ReadTimeout = &to
	v = c.NeedPlainRoundTrip()
	if v != true {
		t.Errorf("Config.NeedPlainRoundTrip is %t, want true", v)
	}

	c.PlainRoundTrip.ReadTimeout = nil
	ru := "data"
	c.PlainRoundTrip.ReadUntil = &ru
	v = c.NeedPlainRoundTrip()
	if v != true {
		t.Errorf("Config.NeedPlainRoundTrip is %t, want true", v)
	}
}

func TestTLSData(t *testing.T) {
	c := Config{}

	v := c.TLSData()
	if v != nil {
		t.Errorf("Config.TLSData is %q, want nil", v)
	}

	c.TLSRoundTrip = &RoundTripOptions{}
	v = c.TLSData()
	if v != nil {
		t.Errorf("Config.TLSData is %q, want nil", v)
	}

	d := "data"
	c.TLSRoundTrip.Send = &d
	v = c.TLSData()
	if string(v) != d {
		t.Errorf("Config.TLSData is %q, want %q", v, d)

	}
}

func TestNeedTLSRoundTrip(t *testing.T) {
	c := Config{}

	v := c.NeedTLSRoundTrip()
	if v != false {
		t.Errorf("Config.NeedTLSRoundTrip is %t, want false", v)
	}

	c.TLSRoundTrip = &RoundTripOptions{}
	v = c.NeedTLSRoundTrip()
	if v != false {
		t.Errorf("Config.NeedTLSRoundTrip is %t, want false", v)
	}

	d := ""
	c.TLSRoundTrip.Send = &d
	v = c.NeedTLSRoundTrip()
	if v != false {
		t.Errorf("Config.NeedTLSRoundTrip is %t, want false", v)
	}

	d = "data"
	c.TLSRoundTrip.Send = &d
	v = c.NeedTLSRoundTrip()
	if v != true {
		t.Errorf("Config.NeedTLSRoundTrip is %t, want true", v)
	}

	c.TLSRoundTrip.Send = nil
	var to int64 = 1
	c.TLSRoundTrip.ReadTimeout = &to
	v = c.NeedTLSRoundTrip()
	if v != true {
		t.Errorf("Config.NeedTLSRoundTrip is %t, want true", v)
	}

	c.TLSRoundTrip.ReadTimeout = nil
	ru := "data"
	c.TLSRoundTrip.ReadUntil = &ru
	v = c.NeedTLSRoundTrip()
	if v != true {
		t.Errorf("Config.NeedTLSRoundTrip is %t, want true", v)
	}

}

func TestTLSReadUntil(t *testing.T) {
	c := Config{}

	v := c.TLSReadUntil()
	if v != nil {
		t.Errorf("Config.TLSReadUntil is %q, want nil", v)
	}

	c.TLSRoundTrip = &RoundTripOptions{}
	v = c.TLSReadUntil()
	if v != nil {
		t.Errorf("Config.TLSReadUntil is %q, want nil", v)
	}

	d := "data"
	c.TLSRoundTrip.ReadUntil = &d
	v = c.TLSReadUntil()
	if string(v) != d {
		t.Errorf("Config.TLSReadUntil is %q, want %q", v, d)

	}
}

func TestPlainReadSize(t *testing.T) {
	c := Config{}
	v := c.PlainReadSize()
	if v != 1024 {
		t.Errorf("Config.ReadSize is %q, want 1024", v)
	}

	c.PlainRoundTrip = &RoundTripOptions{}
	v = c.PlainReadSize()
	if v != 1024 {
		t.Errorf("Config.ReadSize is %q, want 1024", v)
	}

	rs := 1
	c.PlainRoundTrip.ReadSize = &rs
	v = c.PlainReadSize()
	if v != rs {
		t.Errorf("Config.ReadSize is %q, want %q", v, rs)
	}
}
func TestTLSReadSize(t *testing.T) {
	c := Config{}
	v := c.TLSReadSize()
	if v != 1024 {
		t.Errorf("Config.ReadSize is %q, want 1024", v)
	}

	c.TLSRoundTrip = &RoundTripOptions{}
	v = c.TLSReadSize()
	if v != 1024 {
		t.Errorf("Config.ReadSize is %q, want 1024", v)
	}

	rs := 1
	c.TLSRoundTrip.ReadSize = &rs
	v = c.TLSReadSize()
	if v != rs {
		t.Errorf("Config.ReadSize is %q, want %q", v, rs)
	}
}

func TestCheckTrustedByRoot(t *testing.T) {
	c := Config{}
	v := c.CheckTrustedByRoot()
	if !v {
		t.Errorf("Config.CheckTrustedByRoot is %t, want true", v)
	}

	c.Handshake = &HandshakeOptions{}
	v = c.CheckTrustedByRoot()
	if !v {
		t.Errorf("Config.CheckTrustedByRoot is %t, want true", v)
	}

	f := false
	c.Handshake.CheckTrustedByRoot = &f
	v = c.CheckTrustedByRoot()
	if v {
		t.Errorf("Config.CheckTrustedByRoot is %v, want %v", v, f)
	}
}

func TestCheckRevocation(t *testing.T) {
	c := Config{}
	v := c.CheckRevocation()
	if !v {
		t.Errorf("Config.CheckRevocation is %t, want true", v)
	}

	c.Handshake = &HandshakeOptions{}
	v = c.CheckRevocation()
	if !v {
		t.Errorf("Config.CheckRevocation is %t, want true", v)
	}

	f := false
	c.Handshake.CheckRevocation = &f
	v = c.CheckRevocation()
	if v {
		t.Errorf("Config.CheckRevocation is %v, want %v", v, f)
	}
}

func TestCheckNotAfterRemains(t *testing.T) {
	c := Config{}
	now := time.Now()
	v := c.CheckNotAfterRemains()
	if v.Sub(now).Seconds() > 1 {
		t.Errorf("Config.CheckNotAfterRemains returns %q, not now", v)
	}

	c.Handshake = &HandshakeOptions{}
	v = c.CheckNotAfterRemains()
	if v.Sub(now).Seconds() > 1 {
		t.Errorf("Config.CheckNotAfterRemains returns %q, not now", v)
	}

	var day int64 = 1
	c.Handshake.CheckNotAfterRemains = &day
	v = c.CheckNotAfterRemains()
	if v.Sub(now).Seconds()-24*60*60 > 1 {
		t.Errorf("Config.CheckNotAfterRemains returns %q, not 1days after", v)
	}
}

func TestCheckMinRSABitlen(t *testing.T) {
	c := Config{}
	v := c.CheckMinRSABitlen()
	if v != 0 {
		t.Errorf("Config.CheckMinRSABitlen returns %q, not 0", v)
	}

	c.Handshake = &HandshakeOptions{}
	v = c.CheckMinRSABitlen()
	if v != 0 {
		t.Errorf("Config.CheckMinRSABitlen returns %q, not 0", v)
	}

	var len = 1
	c.Handshake.CheckMinRSABitlen = &len
	v = c.CheckMinRSABitlen()
	if v != 1 {
		t.Errorf("Config.CheckMinRSABitlen returns %q, not 1", v)
	}
}

func TestSignatureAlgorithmBlacklist(t *testing.T) {
	c := Config{}
	v := c.SignatureAlgorithmBlacklist()
	if len(v) != 2 {
		t.Errorf("Config.SignatureAlgorithmBlacklist returns %q signatures, not 2", len(v))
	}

	c.Handshake = &HandshakeOptions{}
	v = c.SignatureAlgorithmBlacklist()
	if len(v) != 2 {
		t.Errorf("Config.SignatureAlgorithmBlacklist returns %q signatures, not 2", len(v))
	}

	c.Handshake.SignatureAlgorithmBlacklist = []string{"SHA1WithRSA"}
	v = c.SignatureAlgorithmBlacklist()
	if len(v) != 1 {
		t.Errorf("Config.SignatureAlgorithmBlacklist returns %q, not 1", len(v))
	}
	if v[0] != x509.SHA1WithRSA {
		t.Errorf("Config.SignatureAlgorithmBlacklist returns %q, not %q", v[0], x509.SHA1WithRSA)
	}
}

func TestRootCerts(t *testing.T) {
	c := Config{}
	v := c.RootCerts()
	if v != nil {
		t.Error("Config.RootCerts is not nil, want nil")
	}

	c.Handshake = &HandshakeOptions{}
	v = c.RootCerts()
	if v != nil {
		t.Error("Config.RootCerts is not nil, want nil")
	}

	c.Handshake.RootCerts = []string{string(root.CertPEM)}
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

	c.Handshake = &HandshakeOptions{}
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

	c.Handshake = &HandshakeOptions{}
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

	c.Handshake = &HandshakeOptions{}
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
