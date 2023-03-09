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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/timestamp-authority/pkg/client/mock"
	tsatimestamp "github.com/sigstore/timestamp-authority/pkg/generated/client/timestamp"
	"github.com/sigstore/timestamp-authority/pkg/signer"
)

func TestVerifyArtifactHashedMessages(t *testing.T) {
	c, err := mock.NewTSAClient(mock.TSAClientOptions{Time: time.Now()})
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

		certs, err := cryptoutils.UnmarshalCertificatesFromPEM([]byte(chain.Payload))
		if err != nil {
			t.Fatal("unexpected error while parsing test certificates from PEM file")
		}

		if len(certs) != 3 {
			t.Fatalf("expected three certificates (one leaf, one intermediate, and one root), received %d", len(certs))
		}

		opts := VerifyOpts{
			Intermediates: certs[1:2],
			Roots:         certs[2:],
		}

		ts, err := VerifyTimestampResponse(respBytes.Bytes(), strings.NewReader(tc.message), opts)
		if err != nil {
			t.Errorf("VerifyTimestampResponse failed to verify the timestamp: %v", err)
		}
		if ts == nil {
			t.Error("VerifyTimestampResponse did not return the parsed timestamp as expected")
		}

		if tc.forceError {
			// Force hashed message error mismatch
			msg := tc.message + "XXX"
			ts, err := VerifyTimestampResponse(respBytes.Bytes(), strings.NewReader(msg), opts)
			if err == nil {
				t.Error("expected error message when verifying the timestamp response")
			}
			if err != nil && err.Error() != tc.expectedErrorMessage {
				t.Errorf("expected error message when verifying the timestamp response: %s got %s", tc.expectedErrorMessage, err.Error())
			}
			if ts != nil {
				t.Errorf("expected VerifyTimestampResponse to return a nil Timestamp object")
			}
		}
	}
}

func TestVerifyNonce(t *testing.T) {
	type test struct {
		nonceStr            string
		expectVerifySuccess bool
	}

	tests := []test{
		{
			nonceStr:            "312432523523431424141",
			expectVerifySuccess: true,
		},
		{
			nonceStr:            "9874325235234314241230",
			expectVerifySuccess: false,
		},
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
			t.Fatalf("unexpected failure to create big int from string: %s", tc.nonceStr)
		}

		err := verifyNonce(providedNonce, opts)
		if tc.expectVerifySuccess && err != nil {
			t.Errorf("expected verification to fail \n provided nonce %s should not match opts nonce %s", tc.nonceStr, optsBigIntStr)
		}
		if !tc.expectVerifySuccess && err == nil {
			t.Errorf("expected verification to pass \n provided nonce %s should match opts nonce %s", tc.nonceStr, optsBigIntStr)
		}
	}
}

func TestVerifyLeafCert(t *testing.T) {
	type test struct {
		useOptsCert         bool
		useTSCert           bool
		expectVerifySuccess bool
	}

	tests := []test{
		{
			useOptsCert:         false,
			useTSCert:           false,
			expectVerifySuccess: false,
		},
		{
			useOptsCert:         true,
			useTSCert:           false,
			expectVerifySuccess: true,
		},
		{
			useOptsCert:         false,
			useTSCert:           true,
			expectVerifySuccess: true,
		},
		{
			useOptsCert:         true,
			useTSCert:           true,
			expectVerifySuccess: true,
		},
	}

	for _, tc := range tests {
		criticalExtension := pkix.Extension{
			Id:       EKUOID,
			Critical: true,
		}

		sampleCert := &x509.Certificate{
			Raw:          []byte("abc123"),
			RawIssuer:    []byte("abc123"),
			SerialNumber: big.NewInt(int64(123)),
			Extensions:   []pkix.Extension{criticalExtension},
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
			Subject: pkix.Name{
				CommonName: "TSA-Service",
			},
		}

		opts := VerifyOpts{}
		ts := timestamp.Timestamp{}

		if tc.useOptsCert {
			opts.TSACertificate = sampleCert
			opts.CommonName = sampleCert.Subject.CommonName
		}

		if tc.useTSCert {
			ts.Certificates = []*x509.Certificate{sampleCert}
		}

		err := verifyLeafCert(ts, opts)

		if err != nil && tc.expectVerifySuccess {
			t.Fatalf("expected error to be nil, actual error: %v", err)
		}

		if err == nil && !tc.expectVerifySuccess {
			t.Fatal("expected error not to be nil")
		}
	}
}

func TestVerifyEmbeddedLeafCert(t *testing.T) {
	type test struct {
		optsCert            *x509.Certificate
		providedCert        *x509.Certificate
		expectVerifySuccess bool
	}

	tests := []test{
		{
			optsCert: nil,
			providedCert: &x509.Certificate{
				Raw: []byte("abc123"),
			},
			expectVerifySuccess: true,
		},
		{
			optsCert: &x509.Certificate{
				Raw: []byte("abc123"),
			},
			providedCert: &x509.Certificate{
				Raw: []byte("abc123"),
			},
			expectVerifySuccess: true,
		},
		{
			optsCert: &x509.Certificate{
				Raw: []byte("abc123"),
			},
			providedCert: &x509.Certificate{
				Raw: []byte("def456"),
			},
			expectVerifySuccess: false,
		},
	}

	for _, tc := range tests {
		opts := VerifyOpts{
			TSACertificate: tc.optsCert,
		}

		err := verifyEmbeddedLeafCert(tc.providedCert, opts)
		if err == nil && !tc.expectVerifySuccess {
			t.Errorf("expected verification to fail: provided cert unexpectedly matches opts cert")
		}
		if err != nil && tc.expectVerifySuccess {
			t.Errorf("expected verification to pass: provided cert does not match opts cert")
		}
	}
}

func TestVerifySubjectCommonName(t *testing.T) {
	type test struct {
		optsCommonName      string
		providedCommonName  string
		expectVerifySuccess bool
	}

	tests := []test{
		{
			optsCommonName:      "Sigstore TSA",
			providedCommonName:  "Sigstore TSA",
			expectVerifySuccess: true,
		},
		{
			optsCommonName:      "Sigstore TSA",
			providedCommonName:  "SomeOtherStore",
			expectVerifySuccess: false,
		},
	}
	for _, tc := range tests {
		opts := VerifyOpts{
			CommonName: tc.optsCommonName,
		}

		cert := x509.Certificate{
			Subject: pkix.Name{
				CommonName:   tc.providedCommonName,
				Organization: []string{"Sigstore"},
			},
		}
		err := verifySubjectCommonName(&cert, opts)
		if err != nil && tc.expectVerifySuccess {
			t.Errorf("expected verification to pass \n provided common name %s should match opts common name %s", tc.providedCommonName, tc.optsCommonName)
		}
		if err == nil && !tc.expectVerifySuccess {
			t.Errorf("expected verification to fail \n provided common name %s should not match opts common name %s", tc.providedCommonName, tc.optsCommonName)
		}
	}
}

func TestVerifyESSCertID(t *testing.T) {
	type test struct {
		optsIssuer           pkix.Name
		optsSerialNumber     string
		providedIssuer       pkix.Name
		providedSerialNumber string
		expectVerifySuccess  bool
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
			expectVerifySuccess:  true,
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
			expectVerifySuccess:  false,
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
			expectVerifySuccess:  false,
		},
	}

	for _, tc := range tests {
		optsSerialNumber, ok := new(big.Int).SetString(tc.optsSerialNumber, 10)
		if !ok {
			t.Fatalf("unexpected failure to create big int from string: %s", tc.optsSerialNumber)
		}

		optsRawIssuer, err := json.Marshal(tc.optsIssuer)
		if err != nil {
			t.Fatalf("unexpected failure while marshalling issuer object")
		}
		opts := VerifyOpts{
			TSACertificate: &x509.Certificate{
				Issuer:       tc.optsIssuer,
				RawIssuer:    optsRawIssuer,
				SerialNumber: optsSerialNumber,
			},
		}

		providedSerialNumber, ok := new(big.Int).SetString(tc.providedSerialNumber, 10)
		if !ok {
			t.Fatalf("unexpected failure to create big int from string: %s", tc.providedSerialNumber)
		}

		providedRawIssuer, err := json.Marshal(tc.providedIssuer)
		if err != nil {
			t.Fatalf("unexpected failure while marshalling issuer object")
		}
		cert := x509.Certificate{
			Issuer:       tc.providedIssuer,
			RawIssuer:    providedRawIssuer,
			SerialNumber: providedSerialNumber,
		}
		err = verifyESSCertID(&cert, opts)
		if err != nil && tc.expectVerifySuccess {
			t.Errorf("expected verifcation to pass: %s", err.Error())
		}
		if err == nil && !tc.expectVerifySuccess {
			t.Errorf("expected verifcation to fail")
		}
	}
}

func TestVerifyExtendedKeyUsage(t *testing.T) {
	type test struct {
		eku                 []x509.ExtKeyUsage
		expectVerifySuccess bool
	}

	tests := []test{
		{
			eku:                 []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
			expectVerifySuccess: true,
		},
		{
			eku:                 []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping, x509.ExtKeyUsageIPSECTunnel},
			expectVerifySuccess: false,
		},
		{
			eku:                 []x509.ExtKeyUsage{x509.ExtKeyUsageIPSECTunnel},
			expectVerifySuccess: false,
		},
	}

	for _, tc := range tests {
		cert := x509.Certificate{
			ExtKeyUsage: tc.eku,
		}

		err := verifyExtendedKeyUsage(&cert)
		if err != nil && tc.expectVerifySuccess {
			t.Errorf("expected verifyExtendedKeyUsage to return nil error")
		}
		if err == nil && !tc.expectVerifySuccess {
			t.Errorf("expected verification to fail")
		}
	}
}

func createCertChainAndSigner() ([]*x509.Certificate, *signature.ECDSASignerVerifier, error) {
	sv, _, err := signature.NewECDSASignerVerifier(elliptic.P256(), rand.Reader, crypto.SHA256)
	if err != nil {
		return nil, nil, fmt.Errorf("expected NewECDSASignerVerifier to return a signer verifier: %v", err)
	}

	certChain, err := signer.NewTimestampingCertWithChain(sv)
	if err != nil {
		return nil, nil, fmt.Errorf("expected NewTimestampingCertWithChain to return a certificate chain: %v", err)
	}
	if len(certChain) != 3 {
		return nil, nil, fmt.Errorf("expected the certificate chain to have three certificates: %v", err)
	}

	return certChain, sv, nil
}

func createSignedTimestamp(certChain []*x509.Certificate, sv *signature.ECDSASignerVerifier, tsHasCerts bool) (*timestamp.Timestamp, error) {
	tsq, err := timestamp.CreateRequest(strings.NewReader("TestRequest"), &timestamp.RequestOptions{
		Hash:         crypto.SHA256,
		Certificates: tsHasCerts,
	})
	if err != nil {
		return nil, fmt.Errorf("unexpectedly failed to create timestamp request: %v", err)
	}

	req, err := timestamp.ParseRequest([]byte(tsq))
	if err != nil {
		return nil, fmt.Errorf("unexpectedly failed to parse timestamp request: %v", err)
	}

	tsTemplate := timestamp.Timestamp{
		HashAlgorithm:     req.HashAlgorithm,
		HashedMessage:     req.HashedMessage,
		Time:              time.Now(),
		Policy:            asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 2},
		Ordering:          false,
		Qualified:         false,
		AddTSACertificate: req.Certificates,
		ExtraExtensions:   req.Extensions,
	}

	resp, err := tsTemplate.CreateResponse(certChain[0], sv)
	if err != nil {
		return nil, fmt.Errorf("unexpectedly failed to create timestamp response: %v", err)
	}

	ts, err := timestamp.ParseResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("unexpectedly failed to parse timestamp response: %v", err)
	}

	return ts, nil
}

func TestVerifyTSRWithChain(t *testing.T) {
	certChain, sv, err := createCertChainAndSigner()
	if err != nil {
		t.Errorf("failed to create certificate chain: %v", err)
	}

	tsWithCerts, err := createSignedTimestamp(certChain, sv, true)
	if err != nil {
		t.Errorf("failed to create signed certificate: %v", err)
	}

	tsWithoutCerts, err := createSignedTimestamp(certChain, sv, false)
	if err != nil {
		t.Errorf("failed to create signed certificate: %v", err)
	}

	// get certificates
	leaf := certChain[0]
	intermediate := certChain[1]
	root := certChain[2]

	// invalidate the intermediate certificate
	var invalidIntermediate = *certChain[1]
	invalidIntermediate.RawIssuer = nil
	invalidIntermediate.Issuer = pkix.Name{}

	type test struct {
		name                string
		ts                  *timestamp.Timestamp
		opts                VerifyOpts
		expectVerifySuccess bool
	}

	tests := []test{
		{
			name: "Verification is successful with included leaf certificate in timestamp",
			ts:   tsWithCerts,
			opts: VerifyOpts{
				Roots:         []*x509.Certificate{root},
				Intermediates: []*x509.Certificate{intermediate},
			},
			expectVerifySuccess: true,
		},
		{
			name: "Verification fails due to invalid intermediate certificate",
			ts:   tsWithCerts,
			opts: VerifyOpts{
				Roots:         []*x509.Certificate{root},
				Intermediates: []*x509.Certificate{&invalidIntermediate},
			},
			expectVerifySuccess: false,
		},
		{
			name: "Verification fails due to missing intermediate certificate",
			ts:   tsWithCerts,
			opts: VerifyOpts{
				Roots: []*x509.Certificate{root},
			},
			expectVerifySuccess: false,
		},
		{
			name: "Verification fails due to missing root certificate",
			ts:   tsWithCerts,
			opts: VerifyOpts{
				Intermediates: []*x509.Certificate{intermediate},
			},
			expectVerifySuccess: false,
		},
		{
			name:                "Verification fails due to missing root and intermediate certificates",
			ts:                  tsWithCerts,
			opts:                VerifyOpts{},
			expectVerifySuccess: false,
		},
		{
			name: "Verification fails due to missing leaf certificate",
			ts:   tsWithoutCerts,
			opts: VerifyOpts{
				Roots:         []*x509.Certificate{root},
				Intermediates: []*x509.Certificate{intermediate},
			},
			expectVerifySuccess: false,
		},
		{
			name: "Verification is successful with out of band leaf certificate",
			ts:   tsWithoutCerts,
			opts: VerifyOpts{
				Roots:          []*x509.Certificate{root},
				Intermediates:  []*x509.Certificate{intermediate},
				TSACertificate: leaf,
			},
			expectVerifySuccess: true,
		},
	}

	for _, tc := range tests {
		err = verifyTSRWithChain(tc.ts, tc.opts)
		if tc.expectVerifySuccess && err != nil {
			t.Errorf("test '%s' unexpectedly failed \nExpected verifyTSRWithChain to successfully verify certificate chain, err: %v", tc.name, err)
		} else if !tc.expectVerifySuccess && err == nil {
			t.Errorf("testg '%s' unexpectedly passed \nExpected verifyTSRWithChain to fail verification", tc.name)
		}
	}
}
