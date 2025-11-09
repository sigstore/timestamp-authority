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

package client

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetTimestampClientWithOptions(t *testing.T) {
	t.Parallel()
	expectedUserAgent := "test User-Agent"
	expectedContentType := "application/timestamp-query"
	requestReceived := false
	testServer := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			file := []byte{}

			got := r.UserAgent()
			if got != expectedUserAgent {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			var expectedAccept string
			switch r.URL.Path {
			case "/api/v1/timestamp/certchain":
				expectedAccept = "application/pem-certificate-chain"
			case "/api/v1/timestamp":
				expectedAccept = "application/timestamp-reply"
			}

			accept := r.Header["Accept"][0]
			if accept != expectedAccept {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(file)

			requestReceived = true
		}))
	defer testServer.Close()

	client, err := GetTimestampClient(testServer.URL, WithUserAgent(expectedUserAgent), WithContentType(expectedContentType))
	if err != nil {
		t.Error(err)
	}
	_, _ = client.Timestamp.GetTimestampCertChain(nil)
	if !requestReceived {
		t.Fatal("no requests were received")
	}
	// reset
	requestReceived = false

	_, _, _ = client.Timestamp.GetTimestampResponse(nil, nil)
	if !requestReceived {
		t.Fatal("no requests were received")
	}
}
