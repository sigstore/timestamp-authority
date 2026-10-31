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
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
	ts "github.com/sigstore/timestamp-authority/v2/pkg/generated/restapi/operations/timestamp"
	tsx509 "github.com/sigstore/timestamp-authority/v2/pkg/x509"
	"github.com/sigstore/timestamp-authority/v2/pkg/x509/testutils"
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

func TestTimestampResponseHandlerRejectsCertChainOutsideValidity(t *testing.T) {
	rootCert, rootKey, err := testutils.GenerateRootCa()
	if err != nil {
		t.Fatal(err)
	}
	subCert, subKey, err := testutils.GenerateSubordinateCa(rootCert, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, leafKey, err := testutils.GenerateLeafCert(subCert, subKey)
	if err != nil {
		t.Fatal(err)
	}

	// A chain that expires while the server runs cannot be loaded through
	// NewAPI, which rejects it at startup, so move the dates on a copy instead.
	expired := func(cert *x509.Certificate) *x509.Certificate {
		c := *cert
		c.NotAfter = time.Now().Add(-time.Minute)
		return &c
	}
	notYetValid := func(cert *x509.Certificate) *x509.Certificate {
		c := *cert
		c.NotBefore = time.Now().Add(time.Minute)
		return &c
	}

	tests := []struct {
		name       string
		chain      []*x509.Certificate
		wantIssued bool
	}{
		{name: "valid chain", chain: []*x509.Certificate{leafCert, subCert, rootCert}, wantIssued: true},
		{name: "expired leaf", chain: []*x509.Certificate{expired(leafCert), subCert, rootCert}},
		{name: "expired intermediate", chain: []*x509.Certificate{leafCert, expired(subCert), rootCert}},
		{name: "expired root", chain: []*x509.Certificate{leafCert, subCert, expired(rootCert)}},
		{name: "leaf not yet valid", chain: []*x509.Certificate{notYetValid(leafCert), subCert, rootCert}},
	}

	prevAPI := api
	t.Cleanup(func() { api = prevAPI })

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			api = &API{
				tsaSigner:        leafKey,
				tsaSignerHash:    crypto.SHA256,
				certChain:        tc.chain,
				defaultPolicyOID: tsx509.PolicyOID,
			}

			reqBytes, err := timestamp.CreateRequest(strings.NewReader("artifact"), &timestamp.RequestOptions{Hash: crypto.SHA256})
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodPost, "/api/v1/timestamp", bytes.NewReader(reqBytes))
			r.Header.Set("Content-Type", "application/timestamp-query")

			resp := TimestampResponseHandler(ts.GetTimestampResponseParams{HTTPRequest: r, Request: r.Body})

			if tc.wantIssued {
				if _, ok := resp.(*ts.GetTimestampResponseOK); !ok {
					t.Fatalf("expected a timestamp to be issued, got %T", resp)
				}
				return
			}
			errResp, ok := resp.(*ts.GetTimestampResponseDefault)
			if !ok {
				t.Fatalf("expected an error response, got %T", resp)
			}
			if errResp.Payload.Code != http.StatusInternalServerError {
				t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, errResp.Payload.Code)
			}
			if errResp.Payload.Message != failedToGenerateTimestampResponse {
				t.Fatalf("expected message %q, got %q", failedToGenerateTimestampResponse, errResp.Payload.Message)
			}
		})
	}
}
