package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCertPath string
var rootVerbose bool

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "sslcheck",
	Short: "Verify SSL certificate",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVarP(&rootCertPath, "cert", "c", "", "certificate file")
	rootCmd.PersistentFlags().BoolVarP(&rootVerbose, "verbose", "v", false, "verbose output")
}
