package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var certPathFlag *string
var hostnameFlag *string
var portFlag *string
var version string

func init() {
	fmt.Printf("sslcheck %s\n", version)
	certPathFlag = flag.String("cert", "", ".pem file location. The file must include private key and full certificate chain")
	hostnameFlag = flag.String("hostname", "", "hostname to verify the certificate")
	portFlag = flag.String("port", "", "If port is provided, starts HTTP server on it")
	flag.Parse()
}

func rootHandle(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("OK\n"))
	fmt.Println(req.Method, req.URL)
}

func main() {
	var data []byte
	// Read cert file
	if _, err := os.Stat(*certPathFlag); err == nil {
		data, err = ioutil.ReadFile(*certPathFlag)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	} else {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("Parsing the certificate %s...\n", *certPathFlag)

	certs := extractCerts(data)
	fmt.Printf("  extracted %d certificates\n", len(certs))
	if len(certs) == 0 {
		fmt.Println("Unable to extract certificates")
		os.Exit(1)
	}

	privKey := extractPrivateKey(data)
	if privKey != nil {
		fmt.Println("  extracted 1 private key")
	} else {
		fmt.Println("Private key not found")
		os.Exit(1)
	}

	fmt.Printf("Verifying certificates order... ")
	for idx, item := range certs {
		switch idx {
		case 0:
			if item.IsCA {
				fmt.Println("  cert 0 should not be a CA certificate")
				os.Exit(1)
			}
			break
		default:
			if !item.IsCA {
				fmt.Printf("  cert %d should be a CA certificate", idx)
				os.Exit(1)
			}
			break
		}
	}
	fmt.Println("ok")

	intermediates := x509.NewCertPool()
	for idx, item := range certs {
		if idx != 0 && idx != len(certs)-1 {
			fmt.Printf("Using %s as intermidiate certificate\n", item.Subject)
			intermediates.AddCert(item)
		}
	}

	roots := x509.NewCertPool()
	if len(certs) > 1 {
		rootCert := certs[len(certs)-1]
		fmt.Printf("Using %s as root certificate\n", rootCert.Subject)
		roots.AddCert(certs[len(certs)-1])
	}

	if *hostnameFlag == "" {
		fmt.Println("WARNING: hostname is empty, extracting hostname from the certificate name")
		*hostnameFlag = strings.TrimSuffix(filepath.Base(*certPathFlag), ".pem")
	}

	fmt.Printf("Verifying certificate and chain of trust for hostname %q... ", *hostnameFlag)

	opts := x509.VerifyOptions{
		DNSName:       *hostnameFlag,
		Intermediates: intermediates,
		Roots:         roots,
	}

	if _, err := certs[0].Verify(opts); err != nil {
		fmt.Println("failed to verify certificate: " + err.Error())
		os.Exit(1)
	}
	fmt.Println("ok")

	var cert tls.Certificate
	for _, item := range certs {
		cert.Certificate = append(cert.Certificate, item.Raw)
	}
	cert.PrivateKey = privKey

	fmt.Printf("Verifying private key... ")

	switch pub := certs[0].PublicKey.(type) {
	case *rsa.PublicKey:
		priv, ok := cert.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			fmt.Println("tls: private key type does not match public key type")
			os.Exit(1)
		}
		if pub.N.Cmp(priv.N) != 0 {
			fmt.Println("tls: private key does not match public key")
			os.Exit(1)
		}
	case *ecdsa.PublicKey:
		priv, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			fmt.Println("tls: private key type does not match public key type")
			os.Exit(1)
		}
		if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			fmt.Println("tls: private key does not match public key")
			os.Exit(1)
		}
	case ed25519.PublicKey:
		priv, ok := cert.PrivateKey.(ed25519.PrivateKey)
		if !ok {
			fmt.Println("tls: private key type does not match public key type")
			os.Exit(1)
		}
		if !bytes.Equal(priv.Public().(ed25519.PublicKey), pub) {
			fmt.Println("tls: private key does not match public key")
			os.Exit(1)
		}
	default:
		fmt.Println("tls: unknown public key algorithm")
		os.Exit(1)
	}

	fmt.Println("ok")
	fmt.Printf("Result %s: OK\n", *certPathFlag)

	if *portFlag != "" {
		fmt.Println("Starting HTTP server...")

		http.HandleFunc("/", rootHandle)
		cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
		server := &http.Server{
			Addr:      ":" + *portFlag,
			TLSConfig: cfg,
		}
		log.Fatal(server.ListenAndServeTLS("", ""))
	}
}

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

func extractPrivateKey(data []byte) crypto.PrivateKey {
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
			fmt.Println(err)
			os.Exit(1)
		}
		return item
	}
	return nil
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
