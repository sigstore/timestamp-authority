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
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
	"github.com/sigstore/timestamp-authority/cmd/timestamp-cli/app/format"
	"github.com/sigstore/timestamp-authority/pkg/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func addVerifyFlags(cmd *cobra.Command) {
	cmd.Flags().Var(NewFlagValue(fileFlag, ""), "data", "path to an blob with signed data")
	cmd.Flags().Var(NewFlagValue(fileFlag, ""), "in", "path to timestamp response to verify")
	cmd.Flags().Var(NewFlagValue(fileFlag, ""), "CAfile", "path to certificate chain PEM file")
}

func validateVerifyFlags() error {
	dataStr := viper.GetString("data")
	hashStr := viper.GetString("in")
	caFile := viper.GetString("CAfile")

	if dataStr == "" || hashStr == "" || caFile == "" {
		return errors.New("data, timestamp response file, and CA certificate chain file must be specified")
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
		responseTSR := viper.GetString("in")
		tsrBytes, err := os.ReadFile(filepath.Clean(responseTSR))
		if err != nil {
			return nil, fmt.Errorf("error reading request from file: %w", err)
		}

		ts, err := timestamp.ParseResponse(tsrBytes)
		if err != nil {
			pe := timestamp.ParseError("")
			if errors.As(err, &pe) {
				return nil, fmt.Errorf("Given timestamp response is not valid: %w", err)
			}
			return nil, fmt.Errorf("error parsing response into Timestamp: %w", err)
		}

		p7Message, err := pkcs7.Parse(ts.HashedMessage)
		if err != nil {
			return nil, fmt.Errorf("error parsing hashed message: %w", err)
		}

		certChainPEM := viper.GetString("CAfile")
		pemBytes, err := os.ReadFile(filepath.Clean(certChainPEM))
		if err != nil {
			return nil, fmt.Errorf("error reading request from file: %w", err)
		}

		certPool := x509.NewCertPool()
		ok := certPool.AppendCertsFromPEM(pemBytes)
		if !ok {
			return nil, fmt.Errorf("error while appending certs from PEM")
		}

		err = p7Message.VerifyWithChain(certPool)
		if err != nil {
			return nil, fmt.Errorf("error while verifying with chain: %w", err)
		}

		return nil, nil
	}),
}

func init() {
	initializePFlagMap()
	addVerifyFlags(verifyCmd)
	rootCmd.AddCommand(verifyCmd)
}
