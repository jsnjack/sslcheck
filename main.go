package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
			log.Fatalln(err)
		}
	} else {
		log.Fatalln(err)
	}

	// Parse and extract certificates
	fmt.Printf("Parsing the certificate %s...\n", *certPathFlag)

	certs := extractCerts(data)
	fmt.Printf("  extracted %d certificates\n", len(certs))
	if len(certs) == 0 {
		log.Fatalln("Unable to extract certificates")
	}

	fmt.Printf("Extracting private key... ")
	privKey, err := extractPrivateKey(data)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println("ok")

	if *portFlag != "" {
		fmt.Println("Starting HTTP server...")

		var cert tls.Certificate
		for _, item := range certs {
			cert.Certificate = append(cert.Certificate, item.Raw)
		}
		cert.PrivateKey = privKey

		http.HandleFunc("/", rootHandle)
		cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
		server := &http.Server{
			Addr:      ":" + *portFlag,
			TLSConfig: cfg,
		}
		log.Fatal(server.ListenAndServeTLS("", ""))
	}

	fmt.Printf("Verifying certificates order... ")
	err = verifyOrder(certs)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println("ok")

	fmt.Printf("Verifying private key... ")
	err = verifyPrivateKey(certs[0].PublicKey, privKey)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println("ok")

	if *hostnameFlag == "" {
		fmt.Println("WARNING: hostname is empty, extracting hostname from the certificate name")
		*hostnameFlag = strings.TrimSuffix(filepath.Base(*certPathFlag), ".pem")
	}

	fmt.Printf("Verifying certificate and chain of trust for hostname %q... ", *hostnameFlag)
	err = verifyCertificate(certs, *hostnameFlag)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println("ok")

	fmt.Printf("Result %s: OK\n", *certPathFlag)
}
