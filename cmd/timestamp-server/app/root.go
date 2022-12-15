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

	homedir "github.com/mitchellh/go-homedir"
	"github.com/sigstore/timestamp-authority/pkg/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile     string
	logType     string
	enablePprof bool
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

	rootCmd.PersistentFlags().String("timestamp-signer", "memory", "Timestamping authority signer. Valid options include: [kms, tink, memory, file]. Memory and file-based signers should only be used for testing")
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
