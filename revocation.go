package tlschk

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"io/ioutil"
	"log"
	"net/http"

	"golang.org/x/crypto/ocsp"
)

func isRevokedByOCSP(cert, issuer *x509.Certificate) (bool, error) {
	ocspURLs := cert.OCSPServer
	for _, url := range ocspURLs {
		b, err := ocsp.CreateRequest(cert, issuer, nil)
		if err != nil {
			return false, err
		}
		buf := bytes.NewReader(b)
		resp, err := http.Post(url, "application/ocsp-request", buf)
		if err != nil {
			return false, err
		}
		defer resp.Body.Close()

		body, _ := ioutil.ReadAll(resp.Body)
		ocspResp, err := ocsp.ParseResponse(body, issuer)
		if err != nil {
			return false, err
		}
		if ocspResp == nil {
			return false, nil
		}
		if ocspResp.Status == ocsp.Revoked {
			return true, nil
		}
	}
	return false, nil
}

func getCRL(url string) (*pkix.CertificateList, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return x509.ParseCRL(b)
}

func isRevokedByCRL(cert, issuer *x509.Certificate) bool {
	crlURLs := cert.CRLDistributionPoints
	for _, url := range crlURLs {
		certList, err := getCRL(url)
		if err != nil {
			continue
		}
		err = issuer.CheckCRLSignature(certList)
		if err != nil {
			log.Println(err)
			return false
		}
		revokedList := certList.TBSCertList.RevokedCertificates

		for _, revoked := range revokedList {
			if cert.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
				return true
			}
		}
		return false
	}
	return false
}

func isRevokedCert(cert, issuer *x509.Certificate) bool {
	if len(cert.OCSPServer) != 0 {
		result, err := isRevokedByOCSP(cert, issuer)
		if err == nil {
			return result
		}
	}
	if len(cert.CRLDistributionPoints) != 0 {
		return isRevokedByCRL(cert, issuer)
	}
	return false
}

func isRevokedChain(chain []*x509.Certificate) bool {
	for j, cert := range chain {
		issuerIdx := j + 1
		if j+1 == len(chain) {
			issuerIdx = j
		}
		if isRevokedCert(cert, chain[issuerIdx]) {
			return true
		}
	}
	return false
}
