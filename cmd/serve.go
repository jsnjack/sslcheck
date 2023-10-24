package cmd

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"

	"github.com/spf13/cobra"
)

var servePort int

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve -c <certificate>",
	Short: "Start webserver on provided port",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceErrors = true
		if rootCertPath == "" && rootTargetPath == "" {
			return fmt.Errorf("provide certificate file or directory")
		}
		cmd.SilenceUsage = true
		target := rootTargetPath
		if target == "" {
			target = rootCertPath
		}
		certs, err := NewSSLCertificates(target)
		if err != nil {
			return err
		}

		fmt.Println("Starting webserver...")
		fmt.Printf("  example: curl --resolve *:%d:127.0.0.1 https://example.com:%d -v\n", servePort, servePort)

		// Convert to tls.Certificate
		tlsCerts := []tls.Certificate{}
		for _, item := range certs {
			certToServe := tls.Certificate{}
			certToServe.PrivateKey = item.PrivateKey
			for _, cert := range item.Certificates {
				certToServe.Certificate = append(certToServe.Certificate, cert.Raw)
			}
			tlsCerts = append(tlsCerts, certToServe)
		}
		http.HandleFunc("/", serveHandle)
		cfg := &tls.Config{Certificates: tlsCerts}
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
	serveCmd.Flags().IntVarP(&servePort, "port", "p", 8443, "port to start webserver on")
}

func serveHandle(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("OK\n"))
	fmt.Println(req.Method, req.URL)
}
