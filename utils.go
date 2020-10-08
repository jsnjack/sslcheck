package main

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
	"strings"
	"time"
)

func extractCerts(data []byte) []*x509.Certificate {
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
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println("  found certificate:", item.Subject)
		fmt.Println("             issuer:", item.Issuer)
		fmt.Printf("         expires in: %.0f days\n", item.NotAfter.Sub(time.Now()).Hours()/24)

		if item.NotAfter.Before(time.Now()) {
			fmt.Printf("The certificate has expired on %v\n", item.NotAfter)
			os.Exit(1)
		}
		if item.NotBefore.After(time.Now()) {
			fmt.Printf("The certificate is valid after %v\n", item.NotBefore)
			os.Exit(1)
		}
		certs = append(certs, item)
		fmt.Println()
	}
	return certs
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
	return nil, fmt.Errorf("Private key not found")
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
