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
	"errors"

	"github.com/sigstore/timestamp-authority/cmd/timestamp-cli/app/format"
	"github.com/sigstore/timestamp-authority/pkg/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func addVerifyFlags(cmd *cobra.Command) {
	cmd.Flags().Var(NewFlagValue(fileFlag, ""), "artifact", "path to an artifact with signed data")
	cmd.Flags().Var(NewFlagValue(fileFlag, ""), "in", "path to timestamp response to verify")
	cmd.Flags().Var(NewFlagValue(fileFlag, ""), "CAfile", "path to certificate chain PEM file")
}

func validateVerifyFlags() error {
	artifactStr := viper.GetString("artifact")
	hashStr := viper.GetString("in")
	caFile := viper.GetString("CAfile")

	if artifactStr == "" || hashStr == "" || caFile == "" {
		return errors.New("artifact, timestamp response file, and CA certificate chain file must be specified")
	}

	return nil
}

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify timestamp",
	Long:  "Verify the timestamp response using a timestamp certificate chain.",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			log.CliLogger.Fatal("Error initializing cmd line args: ", err)
		}
		if err := validateVerifyFlags(); err != nil {
			log.Logger.Error(err)
			return err
		}
		return nil
	},
	Run: format.WrapCmd(func(args []string) (interface{}, error) {
		return nil, nil
	}),
}

func init() {
	initializePFlagMap()
	addVerifyFlags(timestampCmd)
	rootCmd.AddCommand(timestampCmd)
}
