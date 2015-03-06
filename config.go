package tlschk

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"strings"
	"time"
)

const (
	defaultReadTimeout      = 0
	defaultConnectTimeout   = 10 * time.Second
	defaultHandshakeTimeout = 10 * time.Second
	defaultRecvSize         = 1024
)

// Config represents tlschk configuration
type Config struct {
	Connect        *ConnectOptions   `json:"connect"`
	PlainRoundTrip *RoundTripOptions `json:"plain_round_trip"`
	Handshake      *HandshakeOptions `json:"handshake"` // TODO: make configurable
	TLSRoundTrip   *RoundTripOptions `json:"tls_round_trip"`
}

// ConnectOptions represents tlschk connect configuration
type ConnectOptions struct {
	Address   *string `json:"address"`
	Port      *int    `json:"port"`
	IPVersion *int64  `json:"ip_version"`
	Timeout   *int64  `json:"timeout"`
}

// HandshakeOptions represents tlschk handshake configuration
type HandshakeOptions struct {
	CipherSuites                []string `json:"cipher_suites"`
	MinVersion                  *string  `json:"min_version"`
	MaxVersion                  *string  `json:"max_version"`
	CheckServername             *string  `json:"check_servername"`
	CheckTrustedByRoot          *bool    `json:"check_trusted_by_root"`
	CheckRevocation             *bool    `json:"check_revocation"`
	CheckNotAfterRemains        *int64   `json:"check_not_after_remains"`
	CheckMinRSABitlen           *int     `json:"check_min_rsa_bitlen"`
	SignatureAlgorithmBlacklist []string `json:"signature_algorithm_blacklist"`
	RootCerts                   []string `json:"root_certs"`
}

// RoundTripOptions represents tlschk roundtrip configuration
type RoundTripOptions struct {
	Send        *string `json:"send"`
	ReadTimeout *int64  `json:"read_timeout"`
	RecvSize    *int    `json:"recv_size"`
	RecvUntil   *string `json:"recv_until"`
}

// NewDefaultConfig returns Config with default parameters
func NewDefaultConfig() *Config {
	return &Config{
		Connect:        &ConnectOptions{},
		PlainRoundTrip: &RoundTripOptions{},
		Handshake:      &HandshakeOptions{},
		TLSRoundTrip:   &RoundTripOptions{},
	}
}

// LoadConfig returns configuratoin
func LoadConfig(reader io.Reader) (*Config, error) {
	errPrefix := "Config error."
	b, err := ioutil.ReadAll(reader)
	if err != nil {
		e := fmt.Errorf("%s Failed to read input. %s", errPrefix, err.Error())
		return nil, e
	}

	conf := &Config{}
	if err := json.Unmarshal(b, conf); err != nil {
		e := fmt.Errorf("%s Failed to load config json. %s", errPrefix, err.Error())
		return nil, e
	}

	if err := conf.Check(); err != nil {
		e := fmt.Errorf("%s %s", errPrefix, err.Error())
		return nil, e
	}
	return conf, nil
}

// Check returns error when configuration is invalid
func (c *Config) Check() error {
	if c.Connect == nil {
		return errors.New("connect is required")
	}
	if c.Connect.Address == nil {
		return errors.New("address is required")
	}
	if c.Connect.Port == nil {
		return errors.New("port is required")
	}
	_, errs := c.rootCerts()
	errStrs := []string{}
	for i, err := range errs {
		if err == nil {
			continue
		}
		errStrs = append(errStrs, fmt.Sprintf("root_certs[%d]: %s", i, err.Error()))
	}
	if len(errStrs) > 0 {
		return errors.New(strings.Join(errStrs, ", "))
	}

	if c.Connect.IPVersion != nil {
		if *c.Connect.IPVersion != 4 && *c.Connect.IPVersion != 6 {
			return errors.New("ip_version allows 4 or 6")
		}
	}

	if _, errs := c.CipherSuites(); errs != nil {
		for _, err := range errs {
			errStrs = append(errStrs, fmt.Sprintf("%s", err.Error()))
		}
		if len(errStrs) > 0 {
			return errors.New(strings.Join(errStrs, ", "))
		}
	}
	if _, err := c.MinVersion(); err != nil {
		return err
	}
	if _, err := c.MaxVersion(); err != nil {
		return err
	}
	return nil
}

// TLSConfig returns tls.Config
func (c *Config) TLSConfig() *tls.Config {
	tlsConf := &tls.Config{}
	tlsConf.InsecureSkipVerify = true
	tlsConf.MinVersion, _ = c.MinVersion()
	tlsConf.MaxVersion, _ = c.MaxVersion()
	tlsConf.CipherSuites, _ = c.CipherSuites()
	tlsConf.Time = c.CheckNotAfterRemains
	return tlsConf
}

// ServerNameForVerify returns servername to use verification
func (c *Config) ServerNameForVerify() *string {
	if c.Handshake == nil {
		return nil
	}
	if c.Handshake.CheckServername == nil {
		return nil
	}
	return c.Handshake.CheckServername
}

// DialNetwork returns network string for dial
func (c *Config) DialNetwork() string {
	base := "tcp"
	if c.Connect == nil {
		return base
	}
	if c.Connect.IPVersion == nil {
		return base
	}
	switch *c.Connect.IPVersion {
	case 4:
		return base + "4"
	case 6:
		return base + "6"
	}
	return base
}

// ConnectTimeout returns timeout(sec) for connection
func (c *Config) ConnectTimeout() time.Duration {
	if c.Connect == nil {
		return defaultConnectTimeout
	}
	if c.Connect.Timeout == nil {
		return defaultConnectTimeout
	}
	return time.Duration(*c.Connect.Timeout) * time.Second
}

// PlainReadTimeout returns timeout(sec) for connection
func (c *Config) PlainReadTimeout() time.Duration {
	if c.PlainRoundTrip == nil {
		return defaultReadTimeout
	}
	if c.PlainRoundTrip.ReadTimeout == nil {
		return defaultReadTimeout
	}
	return time.Duration(*c.PlainRoundTrip.ReadTimeout) * time.Second
}

// TLSReadTimeout returns timeout(sec) for connection
func (c *Config) TLSReadTimeout() time.Duration {
	if c.TLSRoundTrip == nil {
		return defaultReadTimeout
	}
	if c.TLSRoundTrip.ReadTimeout == nil {
		return defaultReadTimeout
	}
	return time.Duration(*c.TLSRoundTrip.ReadTimeout) * time.Second
}

// NeedPlainRoundTrip is returns true when round trip with plain data is needed
func (c *Config) NeedPlainRoundTrip() bool {
	if c.PlainRoundTrip == nil {
		return false
	}
	if c.PlainData() != nil {
		return true
	}
	if c.PlainReadTimeout() != 0 {
		return true
	}
	if c.PlainRecvUntil() != nil {
		return true
	}
	return false
}

// PlainData returns byte data to sending tls socket
func (c *Config) PlainData() []byte {
	if c.PlainRoundTrip == nil {
		return nil
	}
	if c.PlainRoundTrip.Send == nil {
		return nil
	}
	if *c.PlainRoundTrip.Send == "" {
		return nil
	}
	return []byte(*c.PlainRoundTrip.Send)
}

// NeedTLSRoundTrip is returns true when round trip with plain data is needed
func (c *Config) NeedTLSRoundTrip() bool {
	if c.TLSRoundTrip == nil {
		return false
	}
	if c.TLSData() != nil {
		return true
	}
	if c.TLSReadTimeout() != 0 {
		return true
	}
	if c.TLSRecvUntil() != nil {
		return true
	}
	return false
}

// TLSData returns byte data to sending tls socket
func (c *Config) TLSData() []byte {
	if c.TLSRoundTrip == nil {
		return nil
	}
	if c.TLSRoundTrip.Send == nil {
		return nil
	}
	if *c.TLSRoundTrip.Send == "" {
		return nil
	}
	return []byte(*c.TLSRoundTrip.Send)
}

// PlainRecvUntil returns byte data
func (c *Config) PlainRecvUntil() []byte {
	if c.PlainRoundTrip == nil {
		return nil
	}
	if c.PlainRoundTrip.RecvUntil == nil {
		return nil
	}
	return []byte(*c.PlainRoundTrip.RecvUntil)
}

// TLSRecvUntil returns byte data
func (c *Config) TLSRecvUntil() []byte {
	if c.TLSRoundTrip == nil {
		return nil
	}
	if c.TLSRoundTrip.RecvUntil == nil {
		return nil
	}
	return []byte(*c.TLSRoundTrip.RecvUntil)
}

// PlainRecvSize returns buffer size of response
func (c *Config) PlainRecvSize() int {
	if c.PlainRoundTrip == nil {
		return defaultRecvSize
	}
	if c.PlainRoundTrip.RecvSize == nil {
		return defaultRecvSize
	}
	return *c.PlainRoundTrip.RecvSize
}

// TLSRecvSize returns buffer size of response
func (c *Config) TLSRecvSize() int {
	if c.TLSRoundTrip == nil {
		return defaultRecvSize
	}
	if c.TLSRoundTrip.RecvSize == nil {
		return defaultRecvSize
	}
	return *c.TLSRoundTrip.RecvSize
}

// CheckTrustedByRoot returns true if trusted check is enabled
func (c *Config) CheckTrustedByRoot() bool {
	if c.Handshake == nil {
		return true
	}
	if c.Handshake.CheckTrustedByRoot == nil {
		return true
	}

	return *c.Handshake.CheckTrustedByRoot
}

// CheckRevocation returns true if revocation check is enabled
func (c *Config) CheckRevocation() bool {
	if c.Handshake == nil {
		return true
	}
	if c.Handshake.CheckRevocation == nil {
		return true
	}
	return *c.Handshake.CheckRevocation
}

// CheckNotAfterRemains returns time.Time to use verify
func (c *Config) CheckNotAfterRemains() time.Time {
	t := time.Now()
	if c.Handshake == nil {
		return t
	}
	if c.Handshake.CheckNotAfterRemains == nil {
		return t
	}
	d := (time.Duration)(*c.Handshake.CheckNotAfterRemains) * time.Hour * 24
	return t.Add(d)
}

// CheckMinRSABitlen returns min rsa bitlen
func (c *Config) CheckMinRSABitlen() int {
	if c.Handshake == nil {
		return 0
	}
	if c.Handshake.CheckMinRSABitlen == nil {
		return 0
	}
	return *c.Handshake.CheckMinRSABitlen
}

// SignatureAlgorithmBlacklist returns blacklist slice of x509.SignatureAlgorithm
func (c *Config) SignatureAlgorithmBlacklist() []x509.SignatureAlgorithm {
	d := []x509.SignatureAlgorithm{
		x509.MD2WithRSA,
		x509.MD5WithRSA,
	}
	if c.Handshake == nil {
		return d
	}

	if c.Handshake.SignatureAlgorithmBlacklist == nil {
		return d
	}

	list := make([]x509.SignatureAlgorithm, len(c.Handshake.SignatureAlgorithmBlacklist))
	for i, v := range c.Handshake.SignatureAlgorithmBlacklist {
		list[i] = X509SignatureAlgorithm(v)
	}
	return list
}

// RootCerts returns x509.Certificate slice
func (c *Config) RootCerts() []*x509.Certificate {
	certs, _ := c.rootCerts()
	return certs
}

func (c *Config) rootCerts() ([]*x509.Certificate, []error) {
	errs := []error{}
	if c.Handshake == nil {
		return nil, errs
	}
	if c.Handshake.RootCerts == nil {
		return nil, errs
	}

	certs := make([]*x509.Certificate, len(c.Handshake.RootCerts))
	for i, p := range c.Handshake.RootCerts {
		c, err := loadPEMCert(p)
		errs = append(errs, err)
		if err != nil {
			break
		}
		certs[i] = c
	}
	return certs, errs
}

func loadPEMCert(p string) (*x509.Certificate, error) {
	errPrefix := "PEM load error."
	der, _ := pem.Decode([]byte(p))
	if der == nil {
		return nil, fmt.Errorf("%s failed to decode PEM", errPrefix)
	}
	if der.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s PEM data is not certificate", errPrefix)
	}
	x509Cert, err := x509.ParseCertificate(der.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s %s", errPrefix, err.Error())
	}
	return x509Cert, nil
}

// CipherSuites returns uint16 ciphers
func (c *Config) CipherSuites() (ciphers []uint16, errs []error) {
	if c.Handshake == nil {
		return
	}
	for _, cipherStr := range c.Handshake.CipherSuites {
		cipher := TLSCipherInt(cipherStr)
		if cipher == 0 {
			errs = append(errs, fmt.Errorf("%s is not supported", cipherStr))
		} else {
			ciphers = append(ciphers, cipher)
		}
	}
	return
}

func (c *Config) tlsVersion(versionString string) (ver uint16, err error) {
	ver = TLSVersionInt(versionString)
	if ver == 0 {
		err = fmt.Errorf("%s is not supported", versionString)
	}
	return
}

// MinVersion returns min version by uint16
func (c *Config) MinVersion() (ver uint16, err error) {
	if c.Handshake == nil {
		return
	}
	if c.Handshake.MinVersion == nil {
		return
	}
	ver, err = c.tlsVersion(*c.Handshake.MinVersion)
	return
}

// MaxVersion returns min version by uint16
func (c *Config) MaxVersion() (ver uint16, err error) {
	if c.Handshake == nil {
		return
	}
	if c.Handshake.MaxVersion == nil {
		return
	}
	ver, err = c.tlsVersion(*c.Handshake.MaxVersion)
	return
}
