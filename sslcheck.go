package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
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
var serveFlag *bool
var portFlag *string

func init() {
	certPathFlag = flag.String("cert", "", ".pem file location. The file must include private key and full certificate chain")
	hostnameFlag = flag.String("hostname", "", "hostname to verify the certificate")
	serveFlag = flag.Bool("serve", false, "Start HTTP server with provided certificate")
	portFlag = flag.String("port", "443", "Port to start the server on")
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

	intermediates := x509.NewCertPool()
	for idx, item := range certs {
		if idx != 0 && idx != len(certs)-1 {
			intermediates.AddCert(item)
		}
	}

	roots := x509.NewCertPool()
	roots.AddCert(certs[len(certs)-1])

	if *hostnameFlag == "" {
		fmt.Println("WARNING: hostname is empty, extracting hostname from the certificate name")
		*hostnameFlag = strings.TrimSuffix(filepath.Base(*certPathFlag), ".pem")
	}

	opts := x509.VerifyOptions{
		DNSName:       *hostnameFlag,
		Intermediates: intermediates,
		Roots:         roots,
	}

	fmt.Printf("Verifying certificate and chain of trust for hostname %q...", *hostnameFlag)
	if _, err := certs[0].Verify(opts); err != nil {
		fmt.Println("failed to verify certificate: " + err.Error())
		os.Exit(1)
	}
	fmt.Println(" ok")

	var cert tls.Certificate
	for _, item := range certs {
		cert.Certificate = append(cert.Certificate, item.Raw)
	}
	cert.PrivateKey = privKey

	fmt.Printf("Verifying private key...")

	switch pubKey := certs[0].PublicKey.(type) {
	case *rsa.PublicKey:
		if pubKey.N.Cmp(privKey.N) != 0 {
			fmt.Println("private key does not match public key")
			os.Exit(1)
		}
		break
	default:
		fmt.Println("unsupported public key algorithm")
		os.Exit(1)
	}
	fmt.Println(" ok")

	if *serveFlag {
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

func extractPrivateKey(data []byte) *rsa.PrivateKey {
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "PRIVATE KEY" || len(block.Headers) != 0 {
			continue
		}

		item, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		pkey, ok := item.(*rsa.PrivateKey)
		if ok {
			return pkey
		}
	}
	return nil
}
