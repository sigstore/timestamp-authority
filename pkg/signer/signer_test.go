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

package signer

import (
	"context"
	"testing"
)

type testcase struct {
	name             string
	signerHashFunc   string
	expectTestToPass bool
}

func TestNewCryptoSignerSignerHashFunc(t *testing.T) {
	testcases := []testcase{{
		name:             "SHA256",
		signerHashFunc:   "sha256",
		expectTestToPass: true,
	},
		{
			name:             "SHA384",
			signerHashFunc:   "sha384",
			expectTestToPass: true,
		},
		{
			name:             "SHA512",
			signerHashFunc:   "sha512",
			expectTestToPass: true,
		},
		{
			name:             "Empty hash func",
			signerHashFunc:   "",
			expectTestToPass: false,
		},
		{
			name:             "Unsupported hash func",
			signerHashFunc:   "sha224",
			expectTestToPass: false,
		}}

	for _, tc := range testcases {
		_, err := NewCryptoSigner(context.Background(), "memory", "", "", "", "", "", "", tc.signerHashFunc)
		if err != nil && tc.expectTestToPass {
			t.Fatalf("test case '%s' failed: %v", tc.name, err)
		}

		if err == nil && !tc.expectTestToPass {
			t.Fatalf("test case '%s' failed: expected error but got nil", tc.name)
		}
	}
}
