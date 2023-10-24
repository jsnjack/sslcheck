package cmd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SSLCertificate represents a certificate and private key pair
type SSLCertificate struct {
	Certificates []*x509.Certificate
	PrivateKey   crypto.PrivateKey
	raw          []byte
	filename     string
}

// NewSSLCertificate creates a new SSLCertificates
func NewSSLCertificates(target string) ([]*SSLCertificate, error) {
	if target == "" {
		return nil, fmt.Errorf("provide target directory or file")
	}
	info, err := os.Stat(target)

	if err != nil {
		return nil, err
	}

	var certs []*SSLCertificate

	if info.IsDir() {
		entries, err := os.ReadDir(target)
		if err != nil {
			return nil, err
		}
		for _, f := range entries {
			if !f.IsDir() && strings.HasSuffix(f.Name(), ".pem") {
				absPath, err := filepath.Abs(target + "/" + f.Name())
				if err != nil {
					return nil, err
				}
				d, err := os.ReadFile(absPath)
				if err != nil {
					return nil, err
				}
				// Extract certificates
				sslCert, err := createSSLCertificate(d, absPath)
				if err != nil {
					return nil, err
				}
				certs = append(certs, sslCert)
			}
		}
	} else {
		absPath, err := filepath.Abs(target)
		if err != nil {
			return nil, err
		}
		data, err := os.ReadFile(absPath)
		if err != nil {
			return nil, err
		}
		sslCert, err := createSSLCertificate(data, absPath)
		if err != nil {
			return nil, err
		}
		certs = append(certs, sslCert)
	}
	return certs, nil
}

func createSSLCertificate(data []byte, filename string) (*SSLCertificate, error) {
	// Extract certificates
	logf("> Parsing the certificate %s...\n", filename)
	sslCert := &SSLCertificate{raw: data, filename: filename}
	extractedCerts, err := extractCerts(data)
	if err != nil {
		return nil, err
	}
	logf("  extracted %d certificates\n", len(extractedCerts))
	if len(extractedCerts) == 0 {
		return nil, fmt.Errorf("unable to extract certificates")
	}
	sslCert.Certificates = extractedCerts
	// Extract privatekey
	logln("  extracting private key...")
	extractedPK, err := extractPrivateKey(data)
	if err != nil {
		return nil, err
	}
	sslCert.PrivateKey = extractedPK
	return sslCert, nil
}

func extractCerts(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		item, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		format := "%+19s: %s\n"
		logf(format, "found certificate", item.Subject)
		logf(format, "issuer", item.Issuer)
		logf(format, "expires in", fmt.Sprintf("%.0f days\n", time.Until(item.NotAfter).Hours()/24))

		if item.NotAfter.Before(time.Now()) {
			return nil, fmt.Errorf("the certificate has expired on %v", item.NotAfter)
		}
		if item.NotBefore.After(time.Now()) {
			return nil, fmt.Errorf("the certificate is valid after %v", item.NotBefore)
		}
		certs = append(certs, item)
	}
	return certs, nil
}

func extractPrivateKey(data []byte) (crypto.PrivateKey, error) {
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if !strings.Contains(block.Type, "PRIVATE KEY") || len(block.Headers) != 0 {
			continue
		}

		item, err := parsePrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return item, nil
	}
	return nil, fmt.Errorf("private key not found")
}

// Attempt to parse the given private key DER block. OpenSSL 0.9.8 generates
// PKCS#1 private keys by default, while OpenSSL 1.0.0 generates PKCS#8 keys.
// OpenSSL ecparam generates SEC1 EC private keys for ECDSA. We try all three.
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("failed to parse private key")
}

func logf(format string, a ...interface{}) {
	if rootVerbose {
		fmt.Printf(format, a...)
	}
}

func logln(a ...interface{}) {
	if rootVerbose {
		fmt.Println(a...)
	}
}
