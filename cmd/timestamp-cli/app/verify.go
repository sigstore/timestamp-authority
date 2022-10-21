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
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
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

type verifyCmdOutput struct {
	Status string
}

func (t *verifyCmdOutput) String() string {
	return fmt.Sprintf("successfully verified timestamp")
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

		// verify the timestamp response against the CAE chain PEM file
		err = validateTSRWithPEM(ts)
		if err != nil {
			return nil, err
		}

		// validate the timestamp response hashed signature against
		// the local arficat hash

		err = validateArtifactWithTSR(ts)
		if err != nil {
			return nil, err
		}

		return &verifyCmdOutput{Status: "success!"}, nil
	}),
}

func init() {
	initializePFlagMap()
	addVerifyFlags(verifyCmd)
	rootCmd.AddCommand(verifyCmd)
}

func validateTSRWithPEM(ts *timestamp.Timestamp) error {
	p7Message, err := pkcs7.Parse(ts.RawToken)
	if err != nil {
		return fmt.Errorf("error parsing hashed message: %w", err)
	}

	certChainPEM := viper.GetString("CAfile")
	pemBytes, err := os.ReadFile(filepath.Clean(certChainPEM))
	if err != nil {
		return fmt.Errorf("error reading request from file: %w", err)
	}

	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM(pemBytes)
	if !ok {
		return fmt.Errorf("error while appending certs from PEM")
	}

	err = p7Message.VerifyWithChain(certPool)
	if err != nil {
		return fmt.Errorf("error while verifying with chain: %w", err)
	}

	log.CliLogger.Info("verified with chain")

	return nil
}

func validateArtifactWithTSR(ts *timestamp.Timestamp) error {
	dataFilePath := viper.GetString("data")
	dataBytes, err := os.ReadFile(filepath.Clean(dataFilePath))
	if err != nil {
		return err
	}

	h := ts.HashAlgorithm.New()
	b := make([]byte, h.Size())

	r := bytes.NewReader(dataBytes)
	n, err := r.Read(b)
	if err == io.EOF {
		return err
	}

	_, err = h.Write(b[:n])
	if err != nil {
		return fmt.Errorf("failed to create hash")
	}

	localHashedMessage := h.Sum(nil)
	if bytes.Compare(localHashedMessage, ts.HashedMessage) != 0 {
		return fmt.Errorf("hashed messages don't match")
	}

	return nil
}
