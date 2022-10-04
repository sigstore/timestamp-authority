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
	"net/http"
	"net/http/pprof"
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

	rootCmd.PersistentFlags().String("hostname", "timestamp.sigstore.dev", "public hostname of instance")
	rootCmd.PersistentFlags().String("address", "127.0.0.1", "Address to bind to")
	rootCmd.PersistentFlags().String("signer", "memory", "Timestamp signer to use. Valid options include: [gcpkms://resource, azurekms://resource, hashivault://resource, awskms://resource, memory]")
	rootCmd.PersistentFlags().String("certificate-chain-path", "", "PEM encoded certificate chain certifying the timestamp_signer key to act as a timestamping authority")
	rootCmd.PersistentFlags().String("timestamp-signer", "memory", "Timestamping authority signer. Valid options include: [gcpkms://resource, azurekms://resource, hashivault://resource, awskms://resource, memory]")

	rootCmd.PersistentFlags().Uint16("port", 3000, "Port to bind to")

	if err := viper.BindPFlags(rootCmd.PersistentFlags()); err != nil {
		log.Logger.Fatal(err)
	}

	log.Logger.Debugf("pprof enabled: %v", enablePprof)
	// Enable pprof
	if enablePprof {
		go func() {
			mux := http.NewServeMux()

			mux.HandleFunc("/debug/pprof/", pprof.Index)
			mux.HandleFunc("/debug/pprof/{action}", pprof.Index)
			mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)

			if err := http.ListenAndServe(":6060", mux); err != nil && err != http.ErrServerClosed {
				log.Logger.Fatalf("Error when starting or running http server: %v", err)
			}
		}()
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
