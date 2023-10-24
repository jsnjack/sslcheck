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
var verifySkipWildcard bool

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify -c <certificate>",
	Short: "Verify SSL certificate",
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

		if len(certs) > 1 && verifyDomainname == "" {
			return fmt.Errorf("found multiple certificates; provide domain name")
		}

		result := make(map[*SSLCertificate]bool)

		for _, item := range certs {
			logf("> Verifying certificate %s...\n", item.filename)
			result[item] = true

			logln("> Verifying certificates order...")
			err = verifyOrder(item.Certificates)
			if err != nil {
				logln(err.Error())
				result[item] = false
			} else {
				logln("  ok")
			}

			logln("> Verifying private key...")
			err = verifyPrivateKey(item.Certificates[0].PublicKey, item.PrivateKey)
			if err != nil {
				logln(err.Error())
				result[item] = false
			} else {
				logln("  ok")
			}

			logln("> Verifying certificate and chain of trust...")
			if verifyDomainname == "" {
				logln("  WARNING: domain name is empty, extracting domain name from the certificate name")
				verifyDomainname = strings.TrimSuffix(filepath.Base(item.filename), ".pem")
				logf("  Domain name: %q\n", verifyDomainname)
			}
			err = verifyCertificate(item.Certificates, verifyDomainname)
			if err != nil {
				logln(err.Error())
				result[item] = false
			} else {
				logln("  ok")
			}
		}

		isValid := false
		for item, valid := range result {
			if valid {
				fmt.Printf("> Certificate %s is valid\n", item.filename)
				isValid = true
				break
			}
		}

		if !isValid {
			return fmt.Errorf("no valid certificates found")
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
	verifyCmd.Flags().StringVarP(&verifyDomainname, "domain", "d", "", "domain name to use to verify the certificate (default: extracted from the file name)")
	verifyCmd.Flags().BoolVarP(&verifySkipWildcard, "no-wildcard", "w", false, "do not require wildcard certificate")
}

// Verifies certificates order
func verifyOrder(certs []*x509.Certificate) error {
	for idx, item := range certs {
		switch idx {
		case 0:
			if item.IsCA {
				return fmt.Errorf("cert 0 should not be a CA certificate")
			}
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
		logf("  > Using cert [%d] (%s) as root certificate\n", len(certs)-1, rootCert.Subject)
		roots.AddCert(rootCert)
	}
	opts := x509.VerifyOptions{
		DNSName:       hostname,
		Intermediates: intermediates,
		Roots:         roots,
	}

	err := _verifyCertificate(certs[0], opts)
	if err != nil {
		return err
	}

	logf("  > Using the system roots to check if its a self-signed certificate\n")
	opts.Roots = nil
	err = _verifyCertificate(certs[0], opts)
	if err != nil {
		fmt.Printf("> [WARNING] This is a self-signed certificate\n")
	}

	return nil
}

func _verifyCertificate(cert *x509.Certificate, opts x509.VerifyOptions) error {
	// Verify domain name
	logf("    verifying for %q...\n", opts.DNSName)
	if _, err := cert.Verify(opts); err != nil {
		return err
	}

	if !verifySkipWildcard {
		// Verify random subdomain
		opts.DNSName = "_wildcard." + opts.DNSName
		logf("    verifying for %q...\n", opts.DNSName)
		if _, err := cert.Verify(opts); err != nil {
			return fmt.Errorf("not a wildcard certificate")
		}
	} else {
		logln("    skipping wildcard verification")
	}
	return nil
}
