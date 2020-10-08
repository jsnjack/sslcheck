package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

// Verifies certificates order
func verifyOrder(certs []*x509.Certificate) error {
	for idx, item := range certs {
		switch idx {
		case 0:
			if item.IsCA {
				return fmt.Errorf("cert 0 should not be a CA certificate")
			}
			break
		default:
			if !item.IsCA {
				return fmt.Errorf("cert %d should be a CA certificate (intermediate or root)", idx)
			}
		}
	}
	return nil
}

// Verifies that public key matches private key
func verifyPrivateKey(publicKey interface{}, privateKey crypto.PrivateKey) error {
	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		priv, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("tls: private key type does not match public key type")
		}
		if pub.N.Cmp(priv.N) != 0 {
			return fmt.Errorf("tls: private key does not match public key")
		}
	case *ecdsa.PublicKey:
		priv, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return fmt.Errorf("tls: private key type does not match public key type")
		}
		if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			return fmt.Errorf("tls: private key does not match public key")
		}
	case ed25519.PublicKey:
		priv, ok := privateKey.(ed25519.PrivateKey)
		if !ok {
			return fmt.Errorf("tls: private key type does not match public key type")
		}
		if !bytes.Equal(priv.Public().(ed25519.PublicKey), pub) {
			return fmt.Errorf("tls: private key does not match public key")
		}
	default:
		return fmt.Errorf("tls: unknown public key algorithm")
	}
	return nil
}

func verifyCertificate(certs []*x509.Certificate, hostname string) error {
	intermediates := x509.NewCertPool()
	for idx, item := range certs {
		if idx != 0 && idx != len(certs)-1 {
			// fmt.Printf("Using %s as intermidiate certificate\n", item.Subject)
			intermediates.AddCert(item)
		}
	}

	roots := x509.NewCertPool()
	if len(certs) > 1 {
		rootCert := certs[len(certs)-1]
		// fmt.Printf("Using %s as root certificate\n", rootCert.Subject)
		roots.AddCert(rootCert)
	}
	opts := x509.VerifyOptions{
		DNSName:       hostname,
		Intermediates: intermediates,
		Roots:         roots,
	}

	// Verify domain name
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}

	// Verify random subdomain
	opts.DNSName = "veryrandomdomain." + hostname
	if _, err := certs[0].Verify(opts); err != nil {
		return fmt.Errorf("not a vild card certificate")
	}
	return nil
}
