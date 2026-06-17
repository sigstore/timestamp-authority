// Copyright 2025 The Sigstore Authors.
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

package api

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"
)

func FuzzParseJSONRequest(f *testing.F) {
	f.Fuzz(func(_ *testing.T, reqBytes []byte) {
		_, _, _ = ParseJSONRequest(reqBytes)
	})
}

func FuzzParseDERRequest(f *testing.F) {
	f.Fuzz(func(_ *testing.T, reqBytes []byte) {
		_, _, _ = parseDERRequest(reqBytes)
	})
}

func TestParseJSONRequestRejectsOversizeNonce(t *testing.T) {
	hash := base64.StdEncoding.EncodeToString(make([]byte, 32))
	digits := strings.Repeat("9", 200000)
	body := []byte(fmt.Sprintf(`{"artifactHash":%q,"hashAlgorithm":"sha256","nonce":%s}`, hash, digits))

	start := time.Now()
	_, msg, err := ParseJSONRequest(body)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected oversize nonce to be rejected")
	}
	if msg != excessivelyLongNonce {
		t.Fatalf("expected message %q, got %q", excessivelyLongNonce, msg)
	}
	if elapsed > 100*time.Millisecond {
		t.Fatalf("rejection took too long (%v), nonce was parsed before the bound check", elapsed)
	}
}
