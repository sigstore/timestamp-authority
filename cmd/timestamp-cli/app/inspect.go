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
	"path/filepath"

	"github.com/digitorus/timestamp"
	"github.com/sigstore/timestamp-authority/cmd/timestamp-cli/app/format"
	"github.com/sigstore/timestamp-authority/pkg/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func addInspectFlags(cmd *cobra.Command) {
	cmd.Flags().Var(NewFlagValue(fileFlag, ""), "timestamp", "path to timestamp response to inspect")
	cmd.MarkFlagRequired("timestamp") //nolint:errcheck
}

type inspectCmdOutput struct {
	TimestampResponse timestamp.Timestamp
}

func (t *inspectCmdOutput) String() string {
	return fmt.Sprintf("%+v", t.TimestampResponse)
}

var inspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "Inspect timestamp",
	Long:  "Inspect the signed timestamp response.",
	PreRunE: func(cmd *cobra.Command, _ []string) error {
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			log.CliLogger.Fatal("Error initializing cmd line args: ", err)
		}
		return nil
	},
	Run: format.WrapCmd(func(_ []string) (interface{}, error) {
		tsr := viper.GetString("timestamp")
		tsrBytes, err := os.ReadFile(filepath.Clean(tsr))
		if err != nil {
			return nil, fmt.Errorf("Error reading request from TSR file: %w", err)
		}

		ts, err := timestamp.ParseResponse(tsrBytes)
		if err != nil {
			return nil, err
		}

		return &inspectCmdOutput{
			TimestampResponse: *ts,
		}, nil
	}),
}

func init() {
	initializePFlagMap()
	addInspectFlags(inspectCmd)
	rootCmd.AddCommand(inspectCmd)
}
