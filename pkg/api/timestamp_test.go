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
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestGetContentType(t *testing.T) {
	tests := []struct {
		header      string
		wantSubtype string
		wantErr     bool
	}{
		{header: "application/json", wantSubtype: "json"},
		{header: "application/timestamp-query", wantSubtype: "timestamp-query"},
		// A media type parameter must not change the outcome.
		{header: "application/json; charset=utf-8", wantSubtype: "json"},
		{header: "application/timestamp-query; charset=utf-8", wantSubtype: "timestamp-query"},
		// A parameter value that embeds "application/..." must not be
		// mistaken for the media type.
		{header: "multipart/form-data; boundary=application/json", wantErr: true},
		{header: "text/plain", wantErr: true},
		{header: "", wantErr: true},
	}

	for _, tc := range tests {
		r := &http.Request{Header: http.Header{}}
		if tc.header != "" {
			r.Header.Set("Content-Type", tc.header)
		}
		subtype, err := getContentType(r)
		if tc.wantErr {
			if err == nil {
				t.Errorf("header %q: expected an error, got subtype %q", tc.header, subtype)
			}
			continue
		}
		if err != nil {
			t.Errorf("header %q: unexpected error: %v", tc.header, err)
			continue
		}
		if subtype != tc.wantSubtype {
			t.Errorf("header %q: expected subtype %q, got %q", tc.header, tc.wantSubtype, subtype)
		}
	}
}

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

func TestParseJSONRequestRejectsOversizeRequest(t *testing.T) {
	hash := base64.StdEncoding.EncodeToString(make([]byte, 32))
	digits := strings.Repeat("9", 200000)
	body := fmt.Appendf(nil, `{"artifactHash":%q,"hashAlgorithm":"sha256","nonce":%s}`, hash, digits)

	start := time.Now()
	_, msg, err := ParseJSONRequest(body)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected oversize request to be rejected")
	}
	if msg != excessivelyLargeRequest {
		t.Fatalf("expected message %q, got %q", excessivelyLargeRequest, msg)
	}
	if elapsed > 100*time.Millisecond {
		t.Fatalf("rejection took too long (%v), request was parsed before the size check", elapsed)
	}
}
