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

package verification

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
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

func CreateTSR() {}

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
		message              string
		forceError           bool
		expectedErrorMessage string
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
		{
			expectedErrorMessage: "hashed messages don't match",
			forceError:           true,
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

		chain, err := c.Timestamp.GetTimestampCertChain(nil)
		if err != nil {
			t.Fatalf("unexpected error getting timestamp chain: %v", err)
		}

		params := tsatimestamp.NewGetTimestampResponseParams()
		params.SetTimeout(5 * time.Second)
		params.Request = io.NopCloser(bytes.NewReader(tsq))

		var respBytes bytes.Buffer
		_, err = c.Timestamp.GetTimestampResponse(params, &respBytes)
		if err != nil {
			t.Fatalf("unexpected error getting timestamp response: %v", err)
		}

		certPool := x509.NewCertPool()
		ok := certPool.AppendCertsFromPEM([]byte(chain.Payload))
		if !ok {
			t.Fatalf("error parsing response into Timestamp while appending certs from PEM")
		}

		if err := VerifyTimestampResponse(respBytes.Bytes(), strings.NewReader(tc.message), certPool); err != nil {
			t.Errorf("verifyHashedMessages failed comparing hashes: %v", err)
		}

		if tc.forceError {
			// Force hashed message error mismatch
			msg := tc.message + "XXX"
			err := VerifyTimestampResponse(respBytes.Bytes(), strings.NewReader(msg), certPool)
			if err == nil {
				t.Error("expected error message when verifying the timestamp response")
			}
			if err != nil && err.Error() != tc.expectedErrorMessage {
				t.Errorf("expected error message when verifying the timestamp response: %s got %s", tc.expectedErrorMessage, err.Error())
			}
		}
	}
}

func TestVerifyNonce(t *testing.T) {
	type test struct {
		nonceStr string
	}

	tests := []test{
		{nonceStr: "312432523523431424141"},
		{nonceStr: "9874325235234314241230"},
	}

	for _, tc := range tests {
		optsBigIntStr := "312432523523431424141"
		optsNonce, ok := new(big.Int).SetString(optsBigIntStr, 10)
		if !ok {
			t.Fatalf("unexpected failure to create big int from string: %s", optsBigIntStr)
		}
		opts := VerifyOpts{
			Nonce: optsNonce,
		}

		providedNonce, ok := new(big.Int).SetString(tc.nonceStr, 10)
		if !ok {
			t.Fatalf("unexpected failure to create big int from string: %s", optsBigIntStr)
		}

		err := VerifyNonce(providedNonce, opts)
		if providedNonce == optsNonce && err != nil {
			t.Errorf("expected VerifyNonce to return nil error")
		}
		if providedNonce != optsNonce && err == nil {
			t.Errorf("expected VerifyNonce to return non-nil error")
		}
	}
}

func TestVerifyEmbeddedLeafCert(t *testing.T) {
	type test struct {
		optsCert     *x509.Certificate
		providedCert *x509.Certificate
		expectErr    bool
	}

	tests := []test{
		{
			optsCert: nil,
			providedCert: &x509.Certificate{
				Signature: []byte("abc"),
				Version:   123,
			},
			expectErr: false,
		},
		{
			optsCert: &x509.Certificate{
				Signature: []byte("abc"),
				Version:   123,
			},
			providedCert: &x509.Certificate{
				Signature: []byte("abc"),
				Version:   123,
			},
			expectErr: false,
		},
		{
			optsCert: &x509.Certificate{
				Signature: []byte("abcdef"),
				Version:   456,
			},
			providedCert: &x509.Certificate{
				Signature: []byte("abc"),
				Version:   123,
			},
			expectErr: true,
		},
	}

	for _, tc := range tests {
		opts := VerifyOpts{
			TsaCertificate: tc.optsCert,
		}

		err := VerifyEmbeddedLeafCert(tc.providedCert, opts)
		if err == nil && tc.expectErr {
			t.Errorf("expected VerifyEmbeddedLeafCert to return non-nil error")
		}
		if err != nil && !tc.expectErr {
			t.Errorf("expected VerifyEmbeddedLeafCert to return nil error")
		}
	}
}

func TestVerifyLeafCertSubject(t *testing.T) {
	type test struct {
		optsSubject           pkix.Name
		providedSubjectString string
		expectErr             bool
	}

	tests := []test{
		{
			optsSubject: pkix.Name{
				CommonName:   "Sigstore TSA",
				Organization: []string{"Sigstore"},
			},
			providedSubjectString: "CN=Sigstore TSA, O=Sigstore",
			expectErr:             false,
		},
		{
			optsSubject: pkix.Name{
				CommonName:   "Sigstore TSA",
				Organization: []string{"Sigstore"},
			},
			providedSubjectString: "CN=SomeOtherStore TSA, O=SomeOtherStore",
			expectErr:             true,
		},
	}
	for _, tc := range tests {
		opts := VerifyOpts{
			TsaCertificate: &x509.Certificate{
				Subject: tc.optsSubject,
			},
		}
		err := VerifyLeafCertSubject(tc.providedSubjectString, opts)
		if err != nil && !tc.expectErr {
			t.Errorf("expected VerifyLeafCertSubject to return nil error")
		}
		if err == nil && tc.expectErr {
			t.Errorf("expected VerifyLeafCertSubject to return non-nil error")
		}
	}
}

func TestVerifyESSCertID(t *testing.T) {
	type test struct {
		optsIssuer           pkix.Name
		optsSerialNumber     string
		providedIssuer       pkix.Name
		providedSerialNumber string
		expectErr            bool
	}

	tests := []test{
		{
			optsIssuer: pkix.Name{
				CommonName:   "Sigstore CA",
				Organization: []string{"Sigstore"},
			},
			optsSerialNumber: "312432523523431424141",
			providedIssuer: pkix.Name{
				CommonName:   "Sigstore CA",
				Organization: []string{"Sigstore"},
			},
			providedSerialNumber: "312432523523431424141",
			expectErr:            false,
		},
		{
			optsIssuer: pkix.Name{
				CommonName:   "Sigstore CA",
				Organization: []string{"Sigstore"},
			},
			optsSerialNumber: "312432523523431424141",
			providedIssuer: pkix.Name{
				CommonName:   "Sigstore CA",
				Organization: []string{"Sigstore"},
			},
			providedSerialNumber: "4567523523431424141",
			expectErr:            true,
		},
		{
			optsIssuer: pkix.Name{
				CommonName:   "Sigstore CA",
				Organization: []string{"Sigstore"},
			},
			optsSerialNumber: "312432523523431424141",
			providedIssuer: pkix.Name{
				CommonName:   "Another CA",
				Organization: []string{"Sigstore"},
			},
			providedSerialNumber: "312432523523431424141",
			expectErr:            true,
		},
	}

	for _, tc := range tests {
		optsNonce, ok := new(big.Int).SetString(tc.optsSerialNumber, 10)
		if !ok {
			t.Fatalf("unexpected failure to create big int from string: %s", tc.optsSerialNumber)
		}

		opts := VerifyOpts{
			TsaCertificate: &x509.Certificate{
				Issuer:       tc.optsIssuer,
				SerialNumber: optsNonce,
			},
		}

		providedNonce, ok := new(big.Int).SetString(tc.providedSerialNumber, 10)
		if !ok {
			t.Fatalf("unexpected failure to create big int from string: %s", tc.providedSerialNumber)
		}
		cert := x509.Certificate{
			Issuer:       tc.providedIssuer,
			SerialNumber: providedNonce,
		}
		err := VerifyESSCertID(&cert, opts)
		if err != nil && !tc.expectErr {
			t.Errorf("expected VerifyESSCertID to return nil error")
		}
		if err == nil && tc.expectErr {
			t.Errorf("expected VerifyESSCertID to return non-nil error")
		}
	}
}

func TestVerifyExtendedKeyUsage(t *testing.T) {
	type test struct {
		eku       []x509.ExtKeyUsage
		expectErr bool
	}

	tests := []test{
		{
			eku:       []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
			expectErr: false,
		},
		{
			eku:       []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping, x509.ExtKeyUsageIPSECTunnel},
			expectErr: true,
		},
		{
			eku:       []x509.ExtKeyUsage{x509.ExtKeyUsageIPSECTunnel},
			expectErr: true,
		},
	}

	for _, tc := range tests {
		cert := x509.Certificate{
			ExtKeyUsage: tc.eku,
		}

		err := verifyExtendedKeyUsage(&cert)
		if err != nil && !tc.expectErr {
			t.Errorf("expected verifyExtendedKeyUsage to return nil error")
		}
		if err == nil && tc.expectErr {
			t.Errorf("expected verifyExtendedKeyUsage to return non-nil error")
		}
	}
}
