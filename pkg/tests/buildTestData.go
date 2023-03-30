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
	"bytes"
	"crypto"
	"encoding/asn1"
	"encoding/json"
	"strings"
	"testing"

	"github.com/digitorus/timestamp"
	"github.com/sigstore/timestamp-authority/pkg/api"
)

func hashToStr(h crypto.Hash) string {
	switch h {
	case crypto.SHA256:
		return "sha256"
	case crypto.SHA384:
		return "sha384"
	case crypto.SHA512:
		return "sha512"
	default:
		return ""
	}
}

func oidStr(oid asn1.ObjectIdentifier) string {
	return strings.Join(oid, ".")
}

func buildJSONReq(t *testing.T, artifact []byte, opts timestamp.RequestOptions) []byte {
	jsonReq := api.JsonRequest{
		Certificates:  opts.Certificates,
		HashAlgorithm: hashToStr(opts.Hash),
		Artifact:      string(artifact),
		Nonce:         opts.Nonce,
		TSAPolicyOID:  opts.TSAPolicyOID,
	}

	marshalled, err := json.Marshal(jsonReq)
	if err != nil {
		t.Fatalf("failed to marshal request")
	}
	return marshalled
}

func buildTimestampQueryReq(t *testing.T, artifact []byte, opts timestamp.RequestOptions) []byte {
	tsq, err := timestamp.CreateRequest(bytes.NewReader(artifact), &timestamp.RequestOptions{
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
