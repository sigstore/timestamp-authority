//
// Copyright 2022 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package app

import (
	"fmt"
	"os"

	"github.com/go-chi/chi/middleware"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/sigstore/timestamp-authority/v2/pkg/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile                string
	logType                string
	enablePprof            bool
	httpPingOnly           bool
	enforceIntermediateEku bool
	useHTTP201             bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "timestamp-server",
	Short: "Timestamp authority service",
	Long:  `Timestamp authority service that issues signed timestamps`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	//	Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Logger.Error(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.timestamp-server.yaml)")
	rootCmd.PersistentFlags().StringVar(&logType, "log-type", "dev", "logger type to use (dev/prod)")
	rootCmd.PersistentFlags().BoolVar(&enablePprof, "enable-pprof", false, "enable pprof for profiling on port 6060")
	rootCmd.PersistentFlags().BoolVar(&httpPingOnly, "http-ping-only", false, "serve only /ping in the http server")
	rootCmd.PersistentFlags().BoolVar(&enforceIntermediateEku, "enforce-intermediate-eku", true, "enforce requirement for intermediate certificates to have timestamping EKU")
	rootCmd.PersistentFlags().BoolVar(&useHTTP201, "use-http-201", false, "use HTTP 201 Created response code instead of HTTP 200 OK for timestamp responses")
	rootCmd.PersistentFlags().String("timestamp-signer", "memory", "Timestamping authority signer. Valid options include: [kms, tink, memory, file]. Memory and file-based signers should only be used for testing")
	rootCmd.PersistentFlags().String("timestamp-signer-hash", "sha256", "Hash algorithm used by the signer. Must match the hash algorithm specified for a KMS or Tink key. Valid options include: [sha256, sha384, sha512]. Ignored for Memory signer.")
	rootCmd.PersistentFlags().Bool("include-chain-in-response", false, "Whether to include the issuing chain in the timestamp response when certReq is set in the timestamp request. When false, only the leaf certificate is included in the response.")
	// KMS flags
	rootCmd.PersistentFlags().String("kms-key-resource", "", "KMS key for signing timestamp responses. Valid options include: [gcpkms://resource, azurekms://resource, hashivault://resource, awskms://resource]")
	// Tink flags
	rootCmd.PersistentFlags().String("tink-key-resource", "", "KMS key for signing timestamp responses for Tink keysets. Valid options include: [gcp-kms://resource, aws-kms://resource, hcvault://]")
	rootCmd.PersistentFlags().String("tink-keyset-path", "", "Path to KMS-encrypted keyset for Tink, decrypted by tink-key-resource")
	rootCmd.PersistentFlags().String("tink-hcvault-token", "", "Authentication token for Hashicorp Vault API calls")
	// KMS, Tink and File flags
	rootCmd.PersistentFlags().String("certificate-chain-path", "", "Path to PEM-encoded certificate chain certifying the kms-key-resource, tink-key-resource, or file-signer-key-path to act as a timestamping authority")
	// File flags
	rootCmd.PersistentFlags().String("file-signer-key-path", "", "Path to file containing PEM-encoded private key. Supported formats include PKCS#1, PKCS#8, and RFC5915 for EC")
	rootCmd.PersistentFlags().String("file-signer-passwd", "", "Password to decrypt private key")
	// NTP time introspection
	rootCmd.PersistentFlags().String("ntp-monitoring", "", "Path to a file configuring ntp monitoring. Uses pkg/ntpmonitor/ntpsync.yaml as the default configuration if none is provided")
	rootCmd.PersistentFlags().Bool("disable-ntp-monitoring", false, "Disables NTP monitoring. Defaults to false")

	rootCmd.PersistentFlags().String("http-request-id-header-name", middleware.RequestIDHeader, "name of HTTP Request Header to use as request correlation ID")
	rootCmd.PersistentFlags().Uint64("max-request-body-size", 1048576, "Maximum allowed size for request bodies in bytes (1MB by default)")

	if err := viper.BindPFlags(rootCmd.PersistentFlags()); err != nil {
		log.Logger.Fatal(err)
	}
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.SetConfigName("timestamp-server")
		viper.SetConfigType("yaml")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		log.Logger.Infof("Using config file: %s", viper.ConfigFileUsed())
	}
}
