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
	"strings"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"sigs.k8s.io/release-utils/version"

	"github.com/sigstore/timestamp-authority/pkg/log"
)

var rootCmd = &cobra.Command{
	Use:   "timestamp-cli",
	Short: "Timestamp CLI",
	Long:  `Timestamp command line interface tool`,
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		return initConfig(cmd)
	},
}

// Execute runs the base CLI
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.CliLogger.Fatal(err)
	}
}

func init() {
	initializePFlagMap()
	rootCmd.PersistentFlags().String("config", "", "config file (default is $HOME/.timestamp.yaml)")

	rootCmd.PersistentFlags().Var(NewFlagValue(urlFlag, "https://timestamp.sigstore.dev"), "timestamp_server", "Server host:port")
	rootCmd.PersistentFlags().Var(NewFlagValue(formatFlag, "default"), "format", "Command output format")
	rootCmd.PersistentFlags().Var(NewFlagValue(timeoutFlag, "30s"), "timeout", "HTTP timeout")

	// these are bound here and not in PreRun so that all child commands can use them
	if err := viper.BindPFlags(rootCmd.PersistentFlags()); err != nil {
		log.CliLogger.Fatal(err)
	}

	rootCmd.AddCommand(version.Version())
}

func initConfig(cmd *cobra.Command) error {

	viper.SetEnvPrefix("timestamp")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	// manually set all values provided from viper through pflag validation logic
	var changedFlags []string
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if !f.Changed && viper.IsSet(f.Name) {
			changedFlags = append(changedFlags, f.Name)
		}
	})

	for _, flag := range changedFlags {
		val := viper.Get(flag)
		if err := cmd.Flags().Set(flag, fmt.Sprintf("%v", val)); err != nil {
			return err
		}
	}

	if viper.GetString("config") != "" {
		viper.SetConfigFile(viper.GetString("config"))
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			return err
		}

		viper.AddConfigPath(home)
		viper.SetConfigName(".timestamp")
	}

	if err := viper.ReadInConfig(); err != nil {
		switch err.(type) {
		case viper.ConfigFileNotFoundError:
		default:
			return err
		}
	} else if viper.GetString("format") == "default" {
		log.CliLogger.Infof("Using config file:", viper.ConfigFileUsed())
	}

	return nil
}
