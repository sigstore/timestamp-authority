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
	cmd.Flags().Var(NewFlagValue(fileFlag, ""), "certificate-chain", "path to file with PEM-encoded certificate chain. Ordered from intermediate CA certificate that issued the TSA certificate, ending with the root CA certificate.")
	cmd.MarkFlagRequired("certificate-chain") //nolint:errcheck
	cmd.Flags().String("nonce", "", "optional nonce passed with the request")
	cmd.Flags().Var(NewFlagValue(oidFlag, ""), "oid", "optional TSA policy OID passed with the request")
	cmd.Flags().String("subject", "", "expected leaf certificate subject")
	cmd.Flags().Var(NewFlagValue(fileFlag, ""), "certificate", "path to file with PEM-encoded leaf certificate")
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

	certChainPEM := viper.GetString("certificate-chain")
	pemBytes, err := os.ReadFile(filepath.Clean(certChainPEM))
	if err != nil {
		return nil, fmt.Errorf("error reading request from file: %w", err)
	}

	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM(pemBytes)
	if !ok {
		return nil, fmt.Errorf("error parsing response into Timestamp while appending certs from PEM")
	}

	artifactPath := viper.GetString("artifact")
	artifact, err := os.Open(filepath.Clean(artifactPath))
	if err != nil {
		return nil, err
	}

	opts, err := newVerifyOpts()
	if err != nil {
		return verifyCmdOutput{TimestampPath: tsrPath}, fmt.Errorf("failed to created VerifyOpts: %w", err)
	}

	err = verification.VerifyTimestampResponse(tsrBytes, artifact, certPool, opts)

	return &verifyCmdOutput{TimestampPath: tsrPath}, err
}

func newVerifyOpts() (verification.VerifyOpts, error) {
	opts := verification.VerifyOpts{}

	oid, err := getOID()
	if err != nil {
		return verification.VerifyOpts{}, fmt.Errorf("failed to parse value from oid flag: %w", err)
	}
	if oid != nil {
		opts.OID = oid
	}

	certPathFlagVal := viper.GetString("cert")
	if certPathFlagVal != "" {
		cert, err := parseTSACertificate(certPathFlagVal)
		if err != nil {
			return verification.VerifyOpts{}, fmt.Errorf("failed to parse cert flag value from PEM file: %w", err)
		}
		opts.TSACertificate = cert
	}

	roots, intermediates, err := getCerts()
	if err != nil {
		return verification.VerifyOpts{}, fmt.Errorf("failed to parse root and intermediate certs from cert-chain flag: %w", err)
	}
	if roots != nil && intermediates != nil {
		opts.Roots = roots
		opts.Intermediates = intermediates
	}

	nonce, err := getNonce()
	if err != nil {
		return verification.VerifyOpts{}, fmt.Errorf("failed to parse value from nonce flag: %w", err)
	}
	if nonce != nil {
		opts.Nonce = nonce
	}

	subjectFlagVal := viper.GetString("subject")
	if subjectFlagVal != "" {
		opts.Subject = subjectFlagVal
	}

	return opts, nil
}

func getNonce() (*big.Int, error) {
	nonceFlagVal := viper.GetString("nonce")
	if nonceFlagVal == "" {
		return nil, nil
	}

	nonce := new(big.Int)
	nonce, ok := nonce.SetString(nonceFlagVal, 10)
	if !ok {
		return nil, fmt.Errorf("failed to convert string to big.Int")
	}
	return nonce, nil
}

func getCerts() ([]*x509.Certificate, []*x509.Certificate, error) {
	certChainPEM := viper.GetString("cert-chain")
	if certChainPEM == "" {
		return nil, nil, nil
	}

	pemBytes, err := os.ReadFile(filepath.Clean(certChainPEM))
	if err != nil {
		return nil, nil, fmt.Errorf("error reading request from file: %w", err)
	}
	intermediateCerts := []*x509.Certificate{}
	rootCerts := []*x509.Certificate{}
	for len(pemBytes) > 0 {
		block, rest := pem.Decode(pemBytes)
		// if there is nothing left, we have found the last block
		// which should be the root
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse certificate")
		}
		if rest == nil {
			rootCerts = append(rootCerts, cert)
		} else {
			intermediateCerts = append(intermediateCerts, cert)
		}
		pemBytes = rest
	}
	return rootCerts, intermediateCerts, nil
}

func getOID() ([]int, error) {
	oidFlagVal := viper.GetString("oid")
	if oidFlagVal == "" {
		return nil, nil
	}

	oidStrSlice := strings.Split(oidFlagVal, ".")
	oid := make([]int, len(oidStrSlice))
	for i, el := range oidStrSlice {
		intVar, err := strconv.Atoi(el)
		if err != nil {
			return nil, err
		}
		oid[i] = intVar
	}

	return oid, nil
}

func parseTSACertificate(certPath string) (*x509.Certificate, error) {
	pemBytes, err := os.ReadFile(filepath.Clean(certPath))
	if err != nil {
		return nil, fmt.Errorf("error reading TSA's certificate file: %w", err)
	}
	block, rest := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("PEM block is unexpectedly empty")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("PEM block type is not 'PUBLIC KEY'")
	}
	if rest != nil {
		return nil, fmt.Errorf("only expected one certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func init() {
	initializePFlagMap()
	addVerifyFlags(verifyCmd)
	rootCmd.AddCommand(verifyCmd)
}
