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

type verifyCmdOutput struct {
	Status string
}

func (t *verifyCmdOutput) String() string {
	return fmt.Sprintf("successfully verified timestamp")
}

func verifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify timestamp",
		Long:  "Verify the timestamp response using a timestamp certificate chain.",
		Args:  cobra.MinimumNArgs(3),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			initializePFlagMap()
			if err := viper.BindPFlags(cmd.Flags()); err != nil {
				log.CliLogger.Fatal("Error initializing cmd line args: ", err)
			}
			return nil
		},
		Run: format.WrapCmd(func(args []string) (interface{}, error) {
			runVerify()
			return nil, nil
		}),
	}

	cmd.Flags().Var(NewFlagValue(fileFlag, ""), "artifact", "path to an blob with signed data")
	cmd.MarkFlagRequired("artifact")
	cmd.Flags().Var(NewFlagValue(fileFlag, ""), "timestamp", "path to timestamp response to verify")
	cmd.MarkFlagRequired("timestamp")
	cmd.Flags().Var(NewFlagValue(fileFlag, ""), "ca-chain", "path to certificate chain PEM file")
	cmd.MarkFlagRequired("ca-chain")

	return cmd
}

func runVerify() (interface{}, error) {
	tsrPath := viper.GetString("timestamp")
	tsrBytes, err := os.ReadFile(filepath.Clean(tsrPath))
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

	// validate the timestamp response signature against the local arficat hash
	err = validateArtifactWithTSR(ts)
	if err != nil {
		return nil, err
	}

	return &verifyCmdOutput{Status: "success!"}, nil
}

func validateTSRWithPEM(ts *timestamp.Timestamp) error {
	p7Message, err := pkcs7.Parse(ts.RawToken)
	if err != nil {
		return fmt.Errorf("error parsing hashed message: %w", err)
	}

	certChainPEM := viper.GetString("ca-chain")
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
	artifactPath := viper.GetString("artifact")
	artifactBytes, err := os.ReadFile(filepath.Clean(artifactPath))
	if err != nil {
		return err
	}

	h := ts.HashAlgorithm.New()
	b := make([]byte, h.Size())

	r := bytes.NewReader(artifactBytes)
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
