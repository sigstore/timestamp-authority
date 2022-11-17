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
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/digitorus/timestamp"

	"github.com/sigstore/timestamp-authority/cmd/timestamp-cli/app/format"
	"github.com/sigstore/timestamp-authority/pkg/log"
	"github.com/sigstore/timestamp-authority/pkg/verification"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type verifyCmdOutput struct {
	TimestampPath string
}

func (v *verifyCmdOutput) String() string {
	return fmt.Sprintf("Successfully verified timestamp %s", v.TimestampPath)
}

func addVerifyFlags(cmd *cobra.Command) {
	cmd.Flags().Var(NewFlagValue(fileFlag, ""), "artifact", "path to an blob with signed data")
	cmd.MarkFlagRequired("artifact") //nolint:errcheck
	cmd.Flags().Var(NewFlagValue(fileFlag, ""), "timestamp", "path to timestamp response to verify")
	cmd.MarkFlagRequired("timestamp") //nolint:errcheck
	cmd.Flags().Var(NewFlagValue(fileFlag, ""), "cert-chain", "path to certificate chain PEM file")
	cmd.MarkFlagRequired("cert-chain") //nolint:errcheck
	cmd.Flags().String("nonce", "", "optional nonce passed with the request")
	cmd.Flags().Var(NewFlagValue(oidFlag, ""), "oid", "optional oid passed with the request")
	cmd.Flags().String("subject", "", "expected leaf certificate subject")
	cmd.Flags().Var(NewFlagValue(fileFlag, ""), "tsa-cert", "path to TSA cert")
}

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify timestamp",
	Long:  "Verify the timestamp response using a timestamp certificate chain.",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			log.CliLogger.Fatal("Error initializing cmd line args: ", err)
		}
		return nil
	},
	Run: format.WrapCmd(func(args []string) (interface{}, error) {
		return runVerify()
	}),
}

func runVerify() (interface{}, error) {
	tsrPath := viper.GetString("timestamp")
	tsrBytes, err := os.ReadFile(filepath.Clean(tsrPath))
	if err != nil {
		return nil, fmt.Errorf("error reading request from file: %w", err)
	}
	ts, err := timestamp.ParseResponse(tsrBytes)
	if err != nil {
		return nil, err
	}

	certChainPEM := viper.GetString("cert-chain")
	pemBytes, err := os.ReadFile(filepath.Clean(certChainPEM))
	if err != nil {
		return nil, fmt.Errorf("error reading request from file: %w", err)
	}

	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM(pemBytes)
	if !ok {
		return nil, fmt.Errorf("error parsing response into Timestamp while appending certs from PEM")
	}

	tsaCertPath := viper.GetString("tsa-cert")
	pemBytes, err = os.ReadFile(filepath.Clean(tsaCertPath))
	if err != nil {
		return nil, fmt.Errorf("error reading request from file: %w", err)
	}
	block, rest := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return &verifyCmdOutput{TimestampPath: tsrPath}, fmt.Errorf("failed to decode PEM block containing public key")
	}
	if rest != nil {
		return &verifyCmdOutput{TimestampPath: tsrPath}, fmt.Errorf("only expected one certificate")
	}

	tsaCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return &verifyCmdOutput{TimestampPath: tsrPath}, err
	}

	artifactPath := viper.GetString("artifact")
	artifact, err := os.Open(filepath.Clean(artifactPath))
	if err != nil {
		return nil, err
	}

	opts, err := verification.NewVerificationOpts(tsrBytes, artifact, pemBytes)
	if err != nil {
		return nil, err
	}

	reqOIDStr := strings.Split(viper.GetString("oid"), ".")
	reqOID := make([]int, len(reqOIDStr))
	for i, el := range reqOIDStr {
		intVar, err := strconv.Atoi(el)
		if err != nil {
			return nil, err
		}
		reqOID[i] = intVar
	}

	if err := verification.VerifyOID(reqOID, opts); err != nil {
		return &verifyCmdOutput{TimestampPath: tsrPath}, err
	}

	nonce := new(big.Int)
	nonce, ok = nonce.SetString(viper.GetString("nonce"), 10)
	if !ok {
		return &verifyCmdOutput{TimestampPath: tsrPath}, fmt.Errorf("SetString: error")
	}
	if err := verification.VerifyNonce(nonce, opts); err != nil {
		return &verifyCmdOutput{TimestampPath: tsrPath}, err
	}

	if err := verification.VerifyLeafCertSubject(viper.GetString("subject"), opts); err != nil {
		return &verifyCmdOutput{TimestampPath: tsrPath}, err
	}

	if err := verification.VerifyEmbeddedLeafCert(tsaCert, opts); err != nil {
		return &verifyCmdOutput{TimestampPath: tsrPath}, err
	}

	if err := verification.VerifyESSCertID(tsaCert, opts); err != nil {
		return &verifyCmdOutput{TimestampPath: tsrPath}, err
	}

	if verified := verification.VerifyTSRSignature(ts, opts); !verified {
		return nil, err
	}

	err = verification.VerifyTimestampResponse(opts, tsrBytes, artifact, certPool)

	return &verifyCmdOutput{TimestampPath: tsrPath}, err
}

func init() {
	initializePFlagMap()
	addVerifyFlags(verifyCmd)
	rootCmd.AddCommand(verifyCmd)
}
