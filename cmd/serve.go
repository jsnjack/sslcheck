package cmd

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/spf13/cobra"
)

var servePort int

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve -c <certificate>",
	Short: "Start webserver on provided port",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceErrors = true
		data, err := readCert()
		if err != nil {
			return err
		}
		cmd.SilenceUsage = true

		// Parse and extract certificates
		logf("> Parsing the certificate %s...\n", rootCertPath)

		certs, err := extractCerts(data)
		if err != nil {
			return err
		}
		logf("  extracted %d certificates\n", len(certs))
		if len(certs) == 0 {
			return fmt.Errorf("unable to extract certificates")
		}

		logln("> Extracting private key...")
		privKey, err := extractPrivateKey(data)
		if err != nil {
			return err
		}
		logln("  ok")

		fmt.Println("Starting webserver...")
		dnsName := strings.Replace(certs[0].DNSNames[0], "*.", "", 1)
		fmt.Printf("  example: curl --resolve *:%d:127.0.0.1 https://%s:%d -v\n", servePort, dnsName, servePort)

		var cert tls.Certificate
		for _, item := range certs {
			cert.Certificate = append(cert.Certificate, item.Raw)
		}
		cert.PrivateKey = privKey

		http.HandleFunc("/", serveHandle)
		cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
		server := &http.Server{
			Addr:      fmt.Sprintf(":%d", servePort),
			TLSConfig: cfg,
		}
		log.Fatal(server.ListenAndServeTLS("", ""))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// serveCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	serveCmd.Flags().IntVarP(&servePort, "port", "p", 8080, "Port to start webserver on")
}

func serveHandle(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("OK\n"))
	fmt.Println(req.Method, req.URL)
}
