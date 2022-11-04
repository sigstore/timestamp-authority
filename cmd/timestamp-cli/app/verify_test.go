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
	"bytes"
	"crypto"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
	"github.com/sigstore/timestamp-authority/pkg/client"
	tsatimestamp "github.com/sigstore/timestamp-authority/pkg/generated/client/timestamp"
	"github.com/sigstore/timestamp-authority/pkg/server"
	"github.com/spf13/viper"
)

func TestVerifyArtifactHashedMessages(t *testing.T) {
	viper.Set("timestamp-signer", "memory")
	apiServer := server.NewRestAPIServer("localhost", 0, []string{"http"}, 10*time.Second, 10*time.Second)
	server := httptest.NewServer(apiServer.GetHandler())
	t.Cleanup(server.Close)

	c, err := client.GetTimestampClient(server.URL)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	type test struct {
		message string
	}

	tests := []test{
		{
			message: "valid local artifact",
		},
		{
			message: "nonexistant local artifact",
		},
		{
			message: "valid local artifact with hash algorithm",
		},
		{
			message: "valid oid",
		},
		{
			message: "MIIEbjADAgEAMIIEZQYJKoZIhvcNAQcCoIIEVjCCBFICAQExDTALBglghkgBZQMEAgEwgdQGCyqGSIb3DQEJEAEEoIHEBIHBMIG+AgEBBgkrBgEEAYO/MAIwMTANBglghkgBZQMEAgEFAAQgN94hMnpq0onyUi7r1zJHNiLT1/spX8MU2GBN9AdMe6wCFQDS6RL1iVlmlkwJzmpS2EH0cuX8sxgTMjAyMjExMDMxNzQyNDIrMDEwMDADAgEBAhRKnQszZjzcgJkpE8LCbmbF0s1jPaA0pDIwMDEOMAwGA1UEChMFbG9jYWwxHjAcBgNVBAMTFVRlc3QgVFNBIFRpbWVzdGFtcGluZ6CCAckwggHFMIIBaqADAgECAhRHCu9dHKS97mFo1cH5neJubRibujAKBggqhkjOPQQDAjAoMQ4wDAYDVQQKEwVsb2NhbDEWMBQGA1UEAxMNVGVzdCBUU0EgUm9vdDAeFw0yMjExMDMxMTUzMThaFw0zMTExMDMxMTU2MThaMDAxDjAMBgNVBAoTBWxvY2FsMR4wHAYDVQQDExVUZXN0IFRTQSBUaW1lc3RhbXBpbmcwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATo3W6NQrpx5D8z5IvgD2DlAgoJMF4KPY9Pj4UfFhfOq029ryszXp3460Z7N+x86bDvyjVrHaeiPnl1HO9Q52zso2owaDAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFHSIhDdTGIsodML/iUOhx7hgo/K7MB8GA1UdIwQYMBaAFBoZYijuouZCvKDtBd0eCyaU2HWoMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMAoGCCqGSM49BAMCA0kAMEYCIQCmPVr5kwYe4Jg9PGO6apgfzSrKAtESgNHpAbE3iIvJhQIhAJIGNxshJcC8LXHRrVWM77no3d3GguSvR01OAPZwE2pqMYIBmDCCAZQCAQEwQDAoMQ4wDAYDVQQKEwVsb2NhbDEWMBQGA1UEAxMNVGVzdCBUU0EgUm9vdAIURwrvXRykve5haNXB+Z3ibm0Ym7owCwYJYIZIAWUDBAIBoIHqMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMjIxMTAzMTY0MjQyWjAvBgkqhkiG9w0BCQQxIgQgrKbkOizzGoAudPhAnW5Qny788Kcd++VQwPrCMhg4MTEwfQYLKoZIhvcNAQkQAi8xbjBsMGowaAQgXqxJD0nAgg6en9P1bRrU7+6tzxOMn3YThreg7uR6T7EwRDAspCowKDEOMAwGA1UEChMFbG9jYWwxFjAUBgNVBAMTDVRlc3QgVFNBIFJvb3QCFEcK710cpL3uYWjVwfmd4m5tGJu6MAoGCCqGSM49BAMCBEcwRQIgQkc2BxMjnUMzqBDYzUiw10LoCIZ9Zmp1E0Hl6E+9mzwCIQDp2lD826Du5Ss4pNG/TksDknTUJfKvrLc2ex+x+W3VHg==",
		},
	}

	for _, tc := range tests {
		tsq, err := timestamp.CreateRequest(strings.NewReader(tc.message), &timestamp.RequestOptions{
			Hash:         crypto.SHA256,
			Certificates: true,
		})
		if err != nil {
			t.Fatalf("unexpected error creating request: %v", err)
		}

		params := tsatimestamp.NewGetTimestampResponseParams()
		params.SetTimeout(10 * time.Second)
		params.Request = io.NopCloser(bytes.NewReader(tsq))

		var respBytes bytes.Buffer
		_, err = c.Timestamp.GetTimestampResponse(params, &respBytes)
		if err != nil {
			t.Fatalf("unexpected error getting timestamp response: %v", err)
		}

		tsr, err := timestamp.ParseResponse(respBytes.Bytes())
		if err != nil {
			t.Fatalf("unexpected error parsing response: %v", err)
		}

		if err := verifyHashedMessages(tsr.HashAlgorithm.New(), tsr.HashedMessage, strings.NewReader(tc.message)); err != nil {
			t.Errorf("verifyHashedMessages failed comparing hashes: %v", err)
		}

	}
}
