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
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func TestTimestampFlags(t *testing.T) {
	type test struct {
		caseDesc             string
		artifact             string
		hash                 string
		oid                  string
		expectParseSuccess   bool
		expectRequestSuccess bool
	}

	tests := []test{
		{
			caseDesc:             "valid local artifact",
			artifact:             "timestamp.go",
			expectParseSuccess:   true,
			expectRequestSuccess: true,
		},
		{
			caseDesc:             "nonexistant local artifact",
			artifact:             "not_a_file",
			expectParseSuccess:   false,
			expectRequestSuccess: false,
		},
		{
			caseDesc:             "valid local artifact with hash algorithm",
			artifact:             "timestamp.go",
			hash:                 "sha512",
			expectParseSuccess:   true,
			expectRequestSuccess: true,
		},
		{
			caseDesc:             "valid oid",
			artifact:             "timestamp.go",
			oid:                  "1.2.3.4",
			expectParseSuccess:   true,
			expectRequestSuccess: true,
		},
		{
			caseDesc:             "invalid oid",
			artifact:             "timestamp.go",
			oid:                  "1.a.3.4",
			expectParseSuccess:   false,
			expectRequestSuccess: true,
		},
		{
			caseDesc:             "no request or artifact specified",
			expectParseSuccess:   true,
			expectRequestSuccess: false,
		},
	}

	for _, tc := range tests {
		var blankCmd = &cobra.Command{}
		addTimestampFlags(blankCmd)
		args := []string{}

		if tc.artifact != "" {
			args = append(args, "--artifact", tc.artifact)
		}
		if tc.hash != "" {
			args = append(args, "--hash", tc.hash)
		}
		if tc.oid != "" {
			args = append(args, "--tsa-policy", tc.oid)
		}
		if err := blankCmd.ParseFlags(args); (err == nil) != tc.expectParseSuccess {
			t.Errorf("unexpected result parsing '%v': %v", tc.caseDesc, err)
			continue
		}
		if err := viper.BindPFlags(blankCmd.Flags()); err != nil {
			t.Fatalf("unexpected result initializing viper in '%v': %v", tc.caseDesc, err)
		}
		if _, err := createRequestFromFlags(); (err == nil) != tc.expectRequestSuccess {
			t.Errorf("unexpected result creating timestamp request '%v': %v", tc.caseDesc, err)
			continue
		}
	}
}
