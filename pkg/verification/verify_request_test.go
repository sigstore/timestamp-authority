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

package verification

import (
	"crypto"
	"errors"
	"testing"

	"github.com/digitorus/timestamp"
)

func TestVerifyRequest(t *testing.T) {
	tests := []struct {
		name          string
		tsReq         *timestamp.Request
		expectedError error
	}{
		{
			name:          "Valid SHA256",
			tsReq:         &timestamp.Request{HashAlgorithm: crypto.SHA256, HashedMessage: make([]byte, crypto.SHA256.Size())},
			expectedError: nil,
		},
		{
			name:          "Valid SHA384",
			tsReq:         &timestamp.Request{HashAlgorithm: crypto.SHA384, HashedMessage: make([]byte, crypto.SHA384.Size())},
			expectedError: nil,
		},
		{
			name:          "Valid SHA512",
			tsReq:         &timestamp.Request{HashAlgorithm: crypto.SHA512, HashedMessage: make([]byte, crypto.SHA512.Size())},
			expectedError: nil,
		},
		{
			name:          "Weak Hash SHA1",
			tsReq:         &timestamp.Request{HashAlgorithm: crypto.SHA1, HashedMessage: make([]byte, crypto.SHA1.Size())},
			expectedError: ErrWeakHashAlg,
		},
		{
			name:          "Unsupported Hash Algorithm",
			tsReq:         &timestamp.Request{HashAlgorithm: crypto.SHA224, HashedMessage: make([]byte, crypto.SHA224.Size())},
			expectedError: ErrUnsupportedHashAlg,
		},
		{
			name:          "Inconsistent Digest Length",
			tsReq:         &timestamp.Request{HashAlgorithm: crypto.SHA256, HashedMessage: make([]byte, 31)}, // SHA256 size is 32
			expectedError: ErrInconsistentDigestLength,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyRequest(tc.tsReq)
			if tc.expectedError != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tc.expectedError)
				}
				if !errors.Is(err, tc.expectedError) {
					t.Fatalf("expected error to be or wrap %v, but got %v (error message: %q)", tc.expectedError, err, err.Error())
				}
			} else if err != nil {
				t.Fatalf("expected no error, but got %v", err)
			}
		})
	}
}
