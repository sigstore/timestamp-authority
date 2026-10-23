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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/timestamp-authority/v2/pkg/client/mock"
	tsatimestamp "github.com/sigstore/timestamp-authority/v2/pkg/generated/client/timestamp"
	"github.com/sigstore/timestamp-authority/v2/pkg/signer"
	tsx509 "github.com/sigstore/timestamp-authority/v2/pkg/x509"
	"github.com/sigstore/timestamp-authority/v2/pkg/x509/testutils"
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
			message: "nonexistent local artifact",
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
		_, _, err = c.Timestamp.GetTimestampResponse(params, &respBytes)
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
			Intermediates:  certs[1:2],
			Roots:          certs[2:],
			TSACertificate: certs[0],
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
		missingNonce        bool
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
		{
			// A nonce was requested but the response omits it. This must be
			// rejected rather than panicking on the nil comparison.
			missingNonce:        true,
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

		var providedNonce *big.Int
		if !tc.missingNonce {
			providedNonce, ok = new(big.Int).SetString(tc.nonceStr, 10)
			if !ok {
				t.Fatalf("unexpected failure to create big int from string: %s", tc.nonceStr)
			}
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
		onlyCACerts         bool
		expectVerifySuccess bool
		expectedErrMsg      string
	}

	tests := []test{
		{
			useOptsCert:         false,
			useTSCert:           false,
			expectVerifySuccess: false,
			expectedErrMsg:      "signer certificate is required",
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
		// test when a chain only contains CA certificates
		{
			onlyCACerts:         true,
			expectVerifySuccess: false,
			expectedErrMsg:      "signer certificate is required",
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

		var testSigner *x509.Certificate
		if tc.useTSCert || tc.useOptsCert {
			testSigner = sampleCert
		}

		if tc.onlyCACerts {
			sampleCert.IsCA = true
			ts.Certificates = []*x509.Certificate{sampleCert}
		}

		err := verifyLeafCert(testSigner, nil, opts)

		if err != nil && tc.expectVerifySuccess {
			t.Fatalf("expected error to be nil, actual error: %v", err)
		}

		if err != nil && !strings.Contains(err.Error(), tc.expectedErrMsg) {
			t.Fatalf("expected error message %s, got %s", tc.expectedErrMsg, err.Error())
		}

		if err == nil && !tc.expectVerifySuccess {
			t.Fatal("expected error not to be nil")
		}
	}
}

// A certificate that asserts the CA bit but carries the timestamping EKU must
// not be accepted as a TSA leaf, per RFC 3161 2.3.
func TestVerifyLeafCertRejectsCACertificate(t *testing.T) {
	criticalExtension := pkix.Extension{
		Id:       EKUOID,
		Critical: true,
	}

	caCert := &x509.Certificate{
		Raw:                   []byte("abc123"),
		RawIssuer:             []byte("abc123"),
		SerialNumber:          big.NewInt(int64(123)),
		Extensions:            []pkix.Extension{criticalExtension},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
		IsCA:                  true,
		Subject: pkix.Name{
			CommonName: "TSA-Service",
		},
	}

	err := verifyLeafCert(caCert, nil, VerifyOpts{})
	if err == nil {
		t.Fatal("expected verification to fail for a CA certificate used as a timestamping leaf")
	}
	if !strings.Contains(err.Error(), "end-entity") {
		t.Fatalf("expected an end-entity error, got %s", err.Error())
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
			t.Errorf("expected verification to pass: %s", err.Error())
		}
		if err == nil && !tc.expectVerifySuccess {
			t.Errorf("expected verification to fail")
		}
	}
}

func TestVerifyLeafExtendedKeyUsage(t *testing.T) {
	type test struct {
		eku                 []x509.ExtKeyUsage
		unknownEKU          []asn1.ObjectIdentifier
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
		{
			// timestamping plus an unrecognised key purpose OID, which
			// crypto/x509 records under UnknownExtKeyUsage
			eku:                 []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
			unknownEKU:          []asn1.ObjectIdentifier{{1, 2, 3, 4, 5}},
			expectVerifySuccess: false,
		},
		{
			// only an unrecognised key purpose, no timestamping
			unknownEKU:          []asn1.ObjectIdentifier{{1, 2, 3, 4, 5}},
			expectVerifySuccess: false,
		},
	}

	for _, tc := range tests {
		cert := x509.Certificate{
			ExtKeyUsage:        tc.eku,
			UnknownExtKeyUsage: tc.unknownEKU,
		}

		err := verifyLeafExtendedKeyUsage(&cert)
		if err != nil && tc.expectVerifySuccess {
			t.Errorf("expected verifyLeafExtendedKeyUsage to return nil error")
		}
		if err == nil && !tc.expectVerifySuccess {
			t.Errorf("expected verification to fail")
		}
	}
}

func TestVerifyIntermediateExtendedKeyUsage(t *testing.T) {
	type test struct {
		eku                 []x509.ExtKeyUsage
		expectVerifySuccess bool
	}

	tests := []test{
		{
			eku:                 []x509.ExtKeyUsage{},
			expectVerifySuccess: true,
		},
		{
			eku:                 []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
			expectVerifySuccess: true,
		},
		{
			eku:                 []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping, x509.ExtKeyUsageIPSECTunnel},
			expectVerifySuccess: true,
		},
		{
			eku:                 []x509.ExtKeyUsage{x509.ExtKeyUsageAny, x509.ExtKeyUsageIPSECTunnel},
			expectVerifySuccess: true,
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

		err := verifyIntermediateExtendedKeyUsage(&cert)
		if err != nil && tc.expectVerifySuccess {
			t.Errorf("expected verifyIntermediateExtendedKeyUsage to return nil error")
		}
		if err == nil && !tc.expectVerifySuccess {
			t.Errorf("expected verification to fail")
		}
	}
}

func TestVerifyPolicyOIDMatchesSignerKeyType(t *testing.T) {
	ecdsaRootCert, ecdsaRootKey, err := testutils.GenerateRootCa()
	if err != nil {
		t.Fatal(err)
	}
	ecdsaLeafCert, _, err := testutils.GenerateLeafCert(ecdsaRootCert, ecdsaRootKey)
	if err != nil {
		t.Fatal(err)
	}

	mldsaRootCert, mldsaRootKey, err := testutils.GenerateMLDSARootCa()
	if err != nil {
		t.Fatal(err)
	}
	mldsaLeafCert, _, err := testutils.GenerateMLDSALeafCert(mldsaRootCert, mldsaRootKey)
	if err != nil {
		t.Fatal(err)
	}

	customOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5}

	tests := []struct {
		name           string
		policyOID      asn1.ObjectIdentifier
		signerCert     *x509.Certificate
		verifiedChains [][]*x509.Certificate
		expectErr      bool
	}{
		{"non-PQC OID with classical signer", tsx509.PolicyOID, ecdsaLeafCert, [][]*x509.Certificate{{ecdsaLeafCert, ecdsaRootCert}}, false},
		{"non-PQC OID with ML-DSA signer", tsx509.PolicyOID, mldsaLeafCert, [][]*x509.Certificate{{mldsaLeafCert, mldsaRootCert}}, true},
		{"PQC OID with classical signer", tsx509.PolicyOIDPQC, ecdsaLeafCert, [][]*x509.Certificate{{ecdsaLeafCert, ecdsaRootCert}}, true},
		{"PQC OID with ML-DSA signer", tsx509.PolicyOIDPQC, mldsaLeafCert, [][]*x509.Certificate{{mldsaLeafCert, mldsaRootCert}}, false},
		{"custom OID with classical signer", customOID, ecdsaLeafCert, [][]*x509.Certificate{{ecdsaLeafCert, ecdsaRootCert}}, false},
		{"custom OID with ML-DSA signer", customOID, mldsaLeafCert, [][]*x509.Certificate{{mldsaLeafCert, mldsaRootCert}}, false},
		{"non-PQC OID with classical signer and ML-DSA root", tsx509.PolicyOID, ecdsaLeafCert, [][]*x509.Certificate{{ecdsaLeafCert, mldsaRootCert}}, true},
		{"PQC OID with with ML-DSA signer and classical root", tsx509.PolicyOIDPQC, mldsaLeafCert, [][]*x509.Certificate{{mldsaLeafCert, ecdsaRootCert}}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyPolicyOIDMatchesSignerKeyType(tc.policyOID, tc.signerCert, tc.verifiedChains)
			if tc.expectErr && err == nil {
				t.Errorf("expected an error, got nil")
			}
			if !tc.expectErr && err != nil {
				t.Errorf("expected no error, got: %v", err)
			}
		})
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
		Policy:            tsx509.PolicyOID,
		Ordering:          false,
		Qualified:         false,
		AddTSACertificate: req.Certificates,
		ExtraExtensions:   req.Extensions,
	}

	resp, err := tsTemplate.CreateResponseWithOpts(certChain[0], sv, crypto.SHA256)
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

	altCertChain, _, err := createCertChainAndSigner()
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
	altLeaf := altCertChain[0]
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
			name: "Verification fails due to invalid nil root certificate",
			ts:   tsWithCerts,
			opts: VerifyOpts{
				Roots:         []*x509.Certificate{nil},
				Intermediates: []*x509.Certificate{intermediate},
			},
			expectVerifySuccess: false,
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
			name: "Verification succeeds with same certificate embedded and provided",
			ts:   tsWithCerts,
			opts: VerifyOpts{
				Roots:          []*x509.Certificate{root},
				Intermediates:  []*x509.Certificate{intermediate},
				TSACertificate: leaf,
			},
			expectVerifySuccess: true,
		},
		{
			name: "Verification fails with embedded and provided certificate mismatch",
			ts:   tsWithCerts,
			opts: VerifyOpts{
				Roots:          []*x509.Certificate{root},
				Intermediates:  []*x509.Certificate{intermediate},
				TSACertificate: altLeaf,
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
		{
			name: "Verification succeeds with CurrentTime within cert validity",
			ts:   tsWithCerts,
			opts: VerifyOpts{
				Roots:         []*x509.Certificate{root},
				Intermediates: []*x509.Certificate{intermediate},
				CurrentTime:   time.Now(),
			},
			expectVerifySuccess: true,
		},
		{
			name: "Verification fails when CurrentTime is after cert expiry",
			ts:   tsWithCerts,
			opts: VerifyOpts{
				Roots:         []*x509.Certificate{root},
				Intermediates: []*x509.Certificate{intermediate},
				CurrentTime:   time.Now().Add(20 * 365 * 24 * time.Hour),
			},
			expectVerifySuccess: false,
		},
		{
			name: "Verification fails when CurrentTime is before cert validity",
			ts:   tsWithCerts,
			opts: VerifyOpts{
				Roots:         []*x509.Certificate{root},
				Intermediates: []*x509.Certificate{intermediate},
				CurrentTime:   time.Now().Add(-24 * time.Hour),
			},
			expectVerifySuccess: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err = verifyTSRWithChain(tc.ts, tc.opts)
			if tc.expectVerifySuccess && err != nil {
				t.Errorf("unexpectedly failed \nExpected verifyTSRWithChain to successfully verify certificate chain, err: %v", err)
			} else if !tc.expectVerifySuccess && err == nil {
				t.Errorf("unexpectedly passed \nExpected verifyTSRWithChain to fail verification")
			}
		})
	}
}

func createTimestampingLeaf(t *testing.T, parent *x509.Certificate, parentKey crypto.Signer, pub crypto.PublicKey, serial int64, commonName string) *x509.Certificate {
	t.Helper()

	timestampExt, err := asn1.Marshal([]asn1.ObjectIdentifier{tsx509.EKUTimestampingOID})
	if err != nil {
		t.Fatalf("failed to marshal EKU extension: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"local"},
		},
		NotBefore: time.Now().Add(-1 * time.Minute),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		IsCA:      false,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       tsx509.EKUOID,
				Critical: true,
				Value:    timestampExt,
			},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentKey)
	if err != nil {
		t.Fatalf("failed to create leaf certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse leaf certificate: %v", err)
	}
	return cert
}

// resignTimestampResponse signs the TSTInfo of an existing response again
// with the given certificate and key, carrying only the supplied extra signed
// attributes, and wraps the token in a new TimeStampResp.
func resignTimestampResponse(t *testing.T, tsrBytes []byte, cert *x509.Certificate, key crypto.Signer, attrs []pkcs7.Attribute) []byte {
	t.Helper()

	ts, err := timestamp.ParseResponse(tsrBytes)
	if err != nil {
		t.Fatalf("failed to parse timestamp response: %v", err)
	}
	p7, err := pkcs7.Parse(ts.RawToken)
	if err != nil {
		t.Fatalf("failed to parse timestamp token: %v", err)
	}
	sd, err := pkcs7.NewSignedData(p7.Content)
	if err != nil {
		t.Fatalf("failed to create signed data: %v", err)
	}
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	sd.SetContentType(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4})
	sd.GetSignedData().Version = 3
	if err := sd.AddSigner(cert, key, pkcs7.SignerInfoConfig{ExtraSignedAttributes: attrs}); err != nil {
		t.Fatalf("failed to sign timestamp token: %v", err)
	}
	token, err := sd.Finish()
	if err != nil {
		t.Fatalf("failed to finish timestamp token: %v", err)
	}
	resp, err := asn1.Marshal(struct {
		Status         struct{ Status int }
		TimeStampToken asn1.RawValue
	}{TimeStampToken: asn1.RawValue{FullBytes: token}})
	if err != nil {
		t.Fatalf("failed to marshal timestamp response: %v", err)
	}
	return resp
}

// The signed SigningCertificateV2 attribute must identify the certificate the
// token signature is verified with, per RFC 3161 2.4.2 and RFC 5035 4. The
// signer certificate is otherwise selected only by the unsigned SignerInfo
// issuer and serial number.
func TestVerifyTSRWithChainSigningCertificateAttribute(t *testing.T) {
	root, rootKey, err := testutils.GenerateRootCa()
	if err != nil {
		t.Fatalf("failed to generate root CA: %v", err)
	}
	tsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate TSA key: %v", err)
	}
	// two timestamping certificates for the same TSA key
	leafA := createTimestampingLeaf(t, root, rootKey, tsaKey.Public(), 1, "TSA A")
	leafB := createTimestampingLeaf(t, root, rootKey, tsaKey.Public(), 2, "TSA B")

	artifact := "TestRequest"
	digest := sha256.Sum256([]byte(artifact))
	tsTemplate := timestamp.Timestamp{
		HashAlgorithm:     crypto.SHA256,
		HashedMessage:     digest[:],
		Time:              time.Now(),
		Policy:            tsx509.PolicyOID,
		AddTSACertificate: true,
	}
	tsr, err := tsTemplate.CreateResponseWithOpts(leafA, tsaKey, crypto.SHA256)
	if err != nil {
		t.Fatalf("failed to create timestamp response: %v", err)
	}

	signingCertAttr := func(cert *x509.Certificate) pkcs7.Attribute {
		certHash := sha256.Sum256(cert.Raw)
		value, err := asn1.Marshal(signingCertificateV2{Certs: []essCertIDv2{{CertHash: certHash[:]}}})
		if err != nil {
			t.Fatalf("failed to marshal SigningCertificateV2: %v", err)
		}
		return pkcs7.Attribute{Type: signingCertificateV2OID, Value: asn1.RawValue{FullBytes: value}}
	}

	type test struct {
		name           string
		tsr            []byte
		commonName     string
		expectedErrMsg string
	}

	tests := []test{
		{
			name:       "attribute matches the signer certificate",
			tsr:        tsr,
			commonName: "TSA A",
		},
		{
			name:       "attribute matches the signer certificate after re-signing",
			tsr:        resignTimestampResponse(t, tsr, leafB, tsaKey, []pkcs7.Attribute{signingCertAttr(leafB)}),
			commonName: "TSA B",
		},
		{
			name:           "attribute identifies another certificate for the same key",
			tsr:            resignTimestampResponse(t, tsr, leafB, tsaKey, []pkcs7.Attribute{signingCertAttr(leafA)}),
			commonName:     "TSA B",
			expectedErrMsg: "does not match the signer certificate",
		},
		{
			name:           "attribute is missing",
			tsr:            resignTimestampResponse(t, tsr, leafA, tsaKey, nil),
			commonName:     "TSA A",
			expectedErrMsg: "does not contain a signing certificate attribute",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := VerifyOpts{
				Roots:      []*x509.Certificate{root},
				CommonName: tc.commonName,
			}
			_, err := VerifyTimestampResponse(tc.tsr, strings.NewReader(artifact), opts)
			if tc.expectedErrMsg == "" {
				if err != nil {
					t.Fatalf("expected verification to pass: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected verification to fail")
			}
			if !strings.Contains(err.Error(), tc.expectedErrMsg) {
				t.Fatalf("expected error message %s, got %s", tc.expectedErrMsg, err.Error())
			}
		})
	}
}

func TestVerifyTimestampResponseWithOutOfChainCert(t *testing.T) {
	// Read the fixture file: it contains 3 certs
	// * "Spoofed" TSA cert (not issued by the root cert)
	// * TSA cert issued by root cert
	// * root cert
	respBytes, err := os.ReadFile("testdata/response-injected-certs.tsr")
	if err != nil {
		t.Fatalf("failed to read fixture file: %v", err)
	}

	// Parse fixture to find a valid root (or self-signed leaf) to bypass chain verification
	ts, err := timestamp.ParseResponse(respBytes)
	if err != nil {
		t.Fatalf("failed to parse response in test: %v", err)
	}

	// Find the self-signed cert, use as the root
	var validRoots []*x509.Certificate
	for _, cert := range ts.Certificates {
		if cert.Subject.CommonName != "Spoofed TSA" && cert.Issuer.String() == cert.Subject.String() {
			validRoots = append(validRoots, cert)
			break
		}
	}

	opts := VerifyOpts{
		CommonName: "Spoofed TSA", // Ask for the cert that is not part of the chain
		Roots:      validRoots,
	}

	// verify should fail as Spoofed TSA is not signed by root cert
	_, err = VerifyTimestampResponse(respBytes, strings.NewReader("hello"), opts)

	if err == nil {
		t.Errorf("VerifyTimestampResponse succeeded with a certificate that is not part of the cert chain.")
	}
}

func TestVerifyLeafAndIntermediatesTimestampingEKU(t *testing.T) {
	leaf := &x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}

	intermediateAuthorized := &x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}

	intermediateUnrestricted := &x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{},
	}

	intermediateUnauthorized := &x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	root := &x509.Certificate{}

	tests := []struct {
		name        string
		chains      [][]*x509.Certificate
		expectError bool
	}{
		{
			name: "Single chain: Authorized Intermediate",
			chains: [][]*x509.Certificate{
				{leaf, intermediateAuthorized, root},
			},
			expectError: false,
		},
		{
			name: "Single chain: Unrestricted Intermediate",
			chains: [][]*x509.Certificate{
				{leaf, intermediateUnrestricted, root},
			},
			expectError: false,
		},
		{
			name: "Single chain: Unauthorized Intermediate",
			chains: [][]*x509.Certificate{
				{leaf, intermediateUnauthorized, root},
			},
			expectError: true,
		},
		{
			name: "Multiple chains: One unauthorized, one authorized (Cross-signed CA scenario)",
			chains: [][]*x509.Certificate{
				{leaf, intermediateUnauthorized, root},
				{leaf, intermediateAuthorized, root},
			},
			expectError: false,
		},
		{
			name: "Multiple chains: All unauthorized",
			chains: [][]*x509.Certificate{
				{leaf, intermediateUnauthorized, root},
				{leaf, intermediateUnauthorized, root},
			},
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyLeafAndIntermediatesTimestampingEKU(leaf, tc.chains)
			if tc.expectError && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tc.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
