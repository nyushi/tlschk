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
	defaultTimeout  = time.Second * 10
	defaultRecvSize = 1024
)

// Config represents tlschk configuration
type Config struct {
	Address    *string            `json:"address"`
	Port       *int               `json:"port"`
	Connection *connectionOptions `json:"connection"`
	Verify     *verifyOptions     `json:"verify"`
}

type verifyOptions struct {
	CheckServername *string  `json:"check_servername"`
	CheckTrusted    *bool    `json:"check_trusted"`
	CheckRevocation *bool    `json:"check_revocation"`
	RootCerts       []string `json:"root_certs"`
}

type connectionOptions struct {
	IPVersion      *int64  `json:"ip_version"`
	ConnectTimeout *int64  `json:"connect_timeout"`
	ReadTimeout    *int64  `json:"read_timeout"`
	SendPlain      *string `json:"send_plain"`
	SendTLS        *string `json:"send_tls"`
	RecvSize       *int    `json:"recv_size"`
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
	if c.Address == nil {
		return errors.New("address is required")
	}
	if c.Port == nil {
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

	if c.Connection != nil {
		if c.Connection.IPVersion != nil {
			if *c.Connection.IPVersion != 4 && *c.Connection.IPVersion != 6 {
				return errors.New("ip_version allows 4 or 6")
			}
		}
	}
	return nil
}

// TLSConfig returns tls.Config
func (c *Config) TLSConfig() *tls.Config {
	// TODO chipher and protocol specification
	tlsConf := &tls.Config{}
	tlsConf.InsecureSkipVerify = true
	//tlsConf.MinVersion = tls.VersionSSL30
	//tlsConf.MaxVersion = tls.VersionTLS12
	//tlsConf.CipherSuites = []uint16{tls.TLS_RSA_WITH_RC4_128_SHA}
	return tlsConf
}

// ServerNameForVerify returns servername to use verification
func (c *Config) ServerNameForVerify() *string {
	if c.Verify == nil {
		return nil
	}
	if c.Verify.CheckServername == nil {
		return nil
	}
	return c.Verify.CheckServername
}

// DialNetwork returns network string for dial
func (c *Config) DialNetwork() string {
	base := "tcp"
	if c.Connection == nil {
		return base
	}
	if c.Connection.IPVersion == nil {
		return base
	}
	switch *c.Connection.IPVersion {
	case 4:
		return base + "4"
	case 6:
		return base + "6"
	}
	return base
}

// ConnectTimeout returns timeout(sec) for connection
func (c *Config) ConnectTimeout() time.Duration {
	if c.Connection == nil {
		return defaultTimeout
	}
	if c.Connection.ConnectTimeout == nil {
		return defaultTimeout
	}
	return time.Duration(*c.Connection.ConnectTimeout) * time.Second
}

// ReadTimeout returns timeout(sec) for connection
func (c *Config) ReadTimeout() time.Duration {
	if c.Connection == nil {
		return defaultTimeout
	}
	if c.Connection.ReadTimeout == nil {
		return defaultTimeout
	}
	return time.Duration(*c.Connection.ReadTimeout) * time.Second
}

// PlainData returns byte data to sending tls socket
func (c *Config) PlainData() []byte {
	if c.Connection == nil {
		return nil
	}
	if c.Connection.SendPlain == nil {
		return nil
	}
	return []byte(*c.Connection.SendPlain)
}

// TLSData returns byte data to sending tls socket
func (c *Config) TLSData() []byte {
	if c.Connection == nil {
		return nil
	}
	if c.Connection.SendTLS == nil {
		return nil
	}
	return []byte(*c.Connection.SendTLS)
}

// RecvSize returns buffer size of response
func (c *Config) RecvSize() int {
	if c.Connection == nil {
		return defaultRecvSize
	}
	if c.Connection.RecvSize == nil {
		return defaultRecvSize
	}
	return *c.Connection.RecvSize
}

// CheckTrusted returns true if trusted check is enabled
func (c *Config) CheckTrusted() bool {
	if c.Verify == nil {
		return true
	}
	if c.Verify.CheckTrusted == nil {
		return true
	}
	return *c.Verify.CheckTrusted
}

// CheckRevocation returns true if revocation check is enabled
func (c *Config) CheckRevocation() bool {
	if c.Verify == nil {
		return false
	}
	if c.Verify.CheckRevocation == nil {
		return false
	}
	return *c.Verify.CheckRevocation
}

// RootCerts returns x509.Certificate slice
func (c *Config) RootCerts() []*x509.Certificate {
	certs, _ := c.rootCerts()
	return certs
}

func (c *Config) rootCerts() ([]*x509.Certificate, []error) {
	errs := []error{}
	if c.Verify == nil {
		return nil, errs
	}
	if c.Verify.RootCerts == nil {
		return nil, errs
	}

	certs := make([]*x509.Certificate, len(c.Verify.RootCerts))
	for i, p := range c.Verify.RootCerts {
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
