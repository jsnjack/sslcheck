package cmd

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var verifyDomainname string

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify -c <certificate>",
	Short: "Verify SSL certificate",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceErrors = true
		data, err := readCert()
		if err != nil {
			return err
		}
		cmd.SilenceUsage = true

		if !rootVerbose {
			fmt.Printf("> Verifying %s...\n", rootCertPath)
		}

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

		logln("> Verifying certificates order...")
		err = verifyOrder(certs)
		if err != nil {
			return err
		}
		logln("  ok")

		logln("> Verifying private key...")
		err = verifyPrivateKey(certs[0].PublicKey, privKey)
		if err != nil {
			return err
		}
		logln("  ok")

		logln("> Verifying certificate and chain of trust...")
		if verifyDomainname == "" {
			logln("  WARNING: domain name is empty, extracting domain name from the certificate name")
			verifyDomainname = strings.TrimSuffix(filepath.Base(rootCertPath), ".pem")
			logf("  Domain name: %q\n", verifyDomainname)
		}
		err = verifyCertificate(certs, verifyDomainname)
		if err != nil {
			return err
		}
		logln("  ok")

		logf("> Certificate %s: ok\n", rootCertPath)
		if !rootVerbose {
			fmt.Println("  ok")
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// verifyCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	verifyCmd.Flags().StringVarP(&verifyDomainname, "domain", "d", "", "Domain name to use to verify the certificate (default: extracted from the file name)")
}

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
			logf("  Using cert [%d] (%s) as intermidiate certificate\n", idx, item.Subject)
			intermediates.AddCert(item)
		}
	}

	roots := x509.NewCertPool()
	if len(certs) > 1 {
		rootCert := certs[len(certs)-1]
		logf("  Using cert [%d] (%s) as root certificate\n", len(certs)-1, rootCert.Subject)
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
		return fmt.Errorf("not a wildcard certificate")
	}
	return nil
}
