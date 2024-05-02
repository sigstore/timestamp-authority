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
	"crypto"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/digitorus/timestamp"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/timestamp-authority/cmd/timestamp-cli/app/format"
	"github.com/sigstore/timestamp-authority/pkg/client"
	ts "github.com/sigstore/timestamp-authority/pkg/generated/client/timestamp"
	"github.com/sigstore/timestamp-authority/pkg/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func addTimestampFlags(cmd *cobra.Command) {
	cmd.Flags().Var(NewFlagValue(fileFlag, ""), "artifact", "path to an artifact to timestamp")
	cmd.MarkFlagRequired("artifact") //nolint:errcheck
	cmd.Flags().String("hash", "sha256", "hash algorithm to use - Valid values are sha256, sha384, and sha512")
	cmd.Flags().Bool("nonce", true, "specify a pseudo-random nonce in the request")
	cmd.Flags().Bool("certificate", true, "if the timestamp response should contain a certificate chain")
	cmd.Flags().Var(NewFlagValue(oidFlag, ""), "tsa-policy", "optional dotted OID notation for the policy that the TSA should use to create the response")
	cmd.Flags().String("out", "response.tsr", "path to a file to write response.")
}

type timestampCmdOutput struct {
	Timestamp time.Time
	Location  string
}

func (t *timestampCmdOutput) String() string {
	return fmt.Sprintf("Artifact timestamped at %s\nWrote timestamp response to %v\n", t.Timestamp, t.Location)
}

var timestampCmd = &cobra.Command{
	Use:   "timestamp",
	Short: "Signed timestamp command",
	Long:  "Fetches a signed RFC 3161 timestamp. The timestamp response can be verified locally using a timestamp certificate chain.",
	PreRunE: func(cmd *cobra.Command, _ []string) error {
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			log.CliLogger.Fatal("Error initializing cmd line args: ", err)
		}
		return nil
	},
	Run: format.WrapCmd(func(_ []string) (interface{}, error) {
		return runTimestamp()
	}),
}

func createRequestFromFlags() ([]byte, error) {
	artifactStr := viper.GetString("artifact")
	artifactBytes, err := os.ReadFile(filepath.Clean(artifactStr))
	if err != nil {
		return nil, fmt.Errorf("error reading request from file: %w", err)
	}

	var hash crypto.Hash
	switch viper.GetString("hash") {
	case "sha256":
		hash = crypto.SHA256
	case "sha384":
		hash = crypto.SHA384
	case "sha512":
		hash = crypto.SHA512
	default:
		return nil, errors.New("invalid hash algorithm - must be either sha256, sha384, or sha512")
	}

	reqOpts := &timestamp.RequestOptions{
		Hash:         hash,
		Certificates: viper.GetBool("certificate"),
	}

	if viper.GetBool("nonce") {
		nonce, err := cryptoutils.GenerateSerialNumber()
		if err != nil {
			return nil, err
		}
		reqOpts.Nonce = nonce
	}

	if policyStr := viper.GetString("tsa-policy"); policyStr != "" {
		var oidInts []int
		for _, v := range strings.Split(policyStr, ".") {
			i, _ := strconv.Atoi(v)
			oidInts = append(oidInts, i)
		}
		reqOpts.TSAPolicyOID = oidInts
	}

	return timestamp.CreateRequest(bytes.NewReader(artifactBytes), reqOpts)
}

func runTimestamp() (interface{}, error) {
	fmt.Println("Generating a new signed timestamp")

	// Set the Content-Type header to application/timestamp-query for the
	// request that will be made to the server. Since the server accepts
	// both application/timestamp-query and application/json as consumers for
	// the /api/v1/timestamp endpoint, we need to specify which one we want to use
	tsClient, err := client.GetTimestampClient(viper.GetString("timestamp_server"), client.WithUserAgent(UserAgent()), client.WithContentType(client.TimestampQueryMediaType))
	if err != nil {
		return nil, err
	}

	requestBytes, err := createRequestFromFlags()
	if err != nil {
		return nil, err
	}

	params := ts.NewGetTimestampResponseParams()
	params.SetTimeout(viper.GetDuration("timeout"))
	params.Request = io.NopCloser(bytes.NewReader(requestBytes))

	var respBytes bytes.Buffer
	_, err = tsClient.Timestamp.GetTimestampResponse(params, &respBytes)
	if err != nil {
		return nil, err
	}

	// validate that timestamp is parseable
	ts, err := timestamp.ParseResponse(respBytes.Bytes())
	if err != nil {
		return nil, err
	}

	// Write response to file
	outStr := viper.GetString("out")
	if outStr == "" {
		outStr = "response.tsr"
	}
	if err := os.WriteFile(outStr, respBytes.Bytes(), 0600); err != nil {
		return nil, err
	}

	return &timestampCmdOutput{
		Timestamp: ts.Time,
		Location:  outStr,
	}, nil
}

func init() {
	initializePFlagMap()
	addTimestampFlags(timestampCmd)
	rootCmd.AddCommand(timestampCmd)
}
