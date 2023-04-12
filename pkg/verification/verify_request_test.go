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
	"testing"

	"github.com/digitorus/timestamp"
)

func TestVerifyRequest(t *testing.T) {
	tsReq := &timestamp.Request{}

	for _, alg := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		tsReq.HashAlgorithm = alg
		if err := VerifyRequest(tsReq); err != nil {
			t.Fatalf("unexpected error verifying request, got %v", err)
		}
	}

	tsReq.HashAlgorithm = crypto.SHA1
	if err := VerifyRequest(tsReq); err != ErrWeakHashAlg {
		t.Fatalf("expected error with weak hash algorithm, got %v", err)
	}
}
