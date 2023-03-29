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

package tests

import (
	"crypto"
	"encoding/json"
	"io"
	"testing"

	"github.com/digitorus/timestamp"
)

func buildJSONReq(t *testing.T, r io.Reader, opts timestamp.RequestOptions) []byte {
	h := opts.Hash.New()

	b := make([]byte, h.Size())
	for {
		n, err := r.Read(b)
		if err == io.EOF {
			break
		}

		_, err = h.Write(b[:n])
		if err != nil {
			t.Fatalf("failed to create hash")
		}
	}

	finished := h.Sum(nil)

	req := timestamp.Request{
		Certificates:  opts.Certificates,
		HashAlgorithm: crypto.SHA256,
		HashedMessage: finished,
		Nonce:         opts.Nonce,
		TSAPolicyOID:  opts.TSAPolicyOID,
	}

	marshalled, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal request")
	}
	return marshalled
}

func buildTimestampQueryReq(t *testing.T, r io.Reader, opts timestamp.RequestOptions) []byte {
	tsq, err := timestamp.CreateRequest(r, &timestamp.RequestOptions{
		Hash:         crypto.SHA256,
		Certificates: opts.Certificates,
		Nonce:        opts.Nonce,
		TSAPolicyOID: opts.TSAPolicyOID,
	})
	if err != nil {
		t.Fatalf("unexpected error creating request: %v", err)
	}
	return tsq
}
