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
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	ts "github.com/digitorus/timestamp"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/timestamp-authority/v2/pkg/api"
	"github.com/sigstore/timestamp-authority/v2/pkg/client"
	"github.com/sigstore/timestamp-authority/v2/pkg/generated/client/timestamp"
	"github.com/sigstore/timestamp-authority/v2/pkg/x509"
	"github.com/spf13/viper"

	"github.com/go-openapi/runtime"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// TestSigner encapsulates a public key for verification
type TestSigner struct {
	pubKey crypto.PublicKey
}

func (s TestSigner) Public() crypto.PublicKey {
	return s.pubKey
}

// unused
func (s TestSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) (signature []byte, err error) {
	return nil, nil
}

func TestGetTimestampCertChain(t *testing.T) {
	url := createServer(t)

	c, err := client.GetTimestampClient(url)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	chain, err := c.Timestamp.GetTimestampCertChain(nil)
	if err != nil {
		t.Fatalf("unexpected error getting timestamp chain: %v", err)
	}

	certs, err := cryptoutils.UnmarshalCertificatesFromPEM([]byte(chain.Payload))
	if err != nil {
		t.Fatalf("unexpected error unmarshalling cert chain: %v", err)
	}

	signer := TestSigner{pubKey: certs[0].PublicKey}
	if err := x509.VerifyCertChain(certs, signer, true); err != nil {
		t.Fatalf("unexpected error verifying cert chain: %v", err)
	}
}

type timestampTestCase struct {
	name         string
	reqMediaType string
	reqBytes     []byte
	nonce        *big.Int
	includeCerts bool
	policyOID    asn1.ObjectIdentifier
	hash         crypto.Hash
	issuingChain bool
}

func TestGetTimestampResponse(t *testing.T) {
	testArtifact := "blobblobblobblobblobblobblobblobblob"
	testNonce := big.NewInt(1234)
	includeCerts := true
	hashFunc := crypto.SHA256
	hashName := "sha256"
	opts := ts.RequestOptions{
		Nonce:        testNonce,
		Certificates: includeCerts,
		TSAPolicyOID: nil,
		Hash:         hashFunc,
	}

	tests := []timestampTestCase{
		{
			name:         "Timestamp Query Request",
			reqMediaType: client.TimestampQueryMediaType,
			reqBytes:     buildTimestampQueryReq(t, []byte(testArtifact), opts),
			nonce:        testNonce,
			includeCerts: includeCerts,
			hash:         hashFunc,
		},
		{
			name:         "Request with Full Issuing Chain",
			reqMediaType: client.TimestampQueryMediaType,
			reqBytes:     buildTimestampQueryReq(t, []byte(testArtifact), opts),
			nonce:        testNonce,
			includeCerts: includeCerts,
			hash:         hashFunc,
			issuingChain: true,
		},
		{
			name:         "JSON Request",
			reqMediaType: client.JSONMediaType,
			reqBytes:     buildJSONReq(t, []byte(testArtifact), hashFunc, hashName, includeCerts, testNonce, ""),
			nonce:        testNonce,
			includeCerts: includeCerts,
			hash:         hashFunc,
		},
	}

	for _, tc := range tests {
		var url string
		if !tc.issuingChain {
			url = createServer(t, func() { viper.Set("include-chain-in-response", false) })
		} else {
			url = createServer(t, func() { viper.Set("include-chain-in-response", true) })
		}

		c, err := client.GetTimestampClient(url, client.WithContentType(tc.reqMediaType))
		if err != nil {
			t.Fatalf("test '%s': unexpected error creating client: %v", tc.name, err)
		}

		params := timestamp.NewGetTimestampResponseParams()
		params.SetTimeout(10 * time.Second)
		params.Request = io.NopCloser(bytes.NewReader(tc.reqBytes))

		var respBytes bytes.Buffer
		clientOption := func(op *runtime.ClientOperation) {
			op.ConsumesMediaTypes = []string{tc.reqMediaType}
		}
		_, _, err = c.Timestamp.GetTimestampResponse(params, &respBytes, clientOption)
		if err != nil {
			t.Fatalf("test '%s': unexpected error getting timestamp response: %v", tc.name, err)
		}

		tsr, err := ts.ParseResponse(respBytes.Bytes())
		if err != nil {
			t.Fatalf("test '%s': unexpected error parsing response: %v", tc.name, err)
		}

		// check certificate fields
		if !tsr.AddTSACertificate {
			t.Fatalf("test '%s': expected TSA certificate", tc.name)
		}
		if !tc.issuingChain {
			if len(tsr.Certificates) != 1 {
				t.Fatalf("test '%s': expected 1 certificate, got %d", tc.name, len(tsr.Certificates))
			}
			if tsr.Certificates[0].Subject.CommonName != "Test TSA Timestamping" {
				t.Fatalf("test '%s': expected subject to be 'Test TSA Timestamping', got %s", tc.name, tsr.Certificates[0].Subject.CommonName)
			}
		} else {
			if len(tsr.Certificates) != 3 {
				t.Fatalf("test '%s': expected 3 certificates, got %d", tc.name, len(tsr.Certificates))
			}
			if tsr.Certificates[0].Subject.CommonName != "Test TSA Timestamping" {
				t.Fatalf("test '%s': expected subject to be 'Test TSA Timestamping', got %s", tc.name, tsr.Certificates[0].Subject.CommonName)
			}
			if tsr.Certificates[1].Subject.CommonName != "Test TSA Intermediate" {
				t.Fatalf("test '%s': expected subject to be 'Test TSA Intermediate', got %s", tc.name, tsr.Certificates[1].Subject.CommonName)
			}
			if tsr.Certificates[2].Subject.CommonName != "Test TSA Root" {
				t.Fatalf("test '%s': expected subject to be 'Test TSA Root', got %s", tc.name, tsr.Certificates[2].Subject.CommonName)
			}
		}
		// check nonce
		if tsr.Nonce.Cmp(tc.nonce) != 0 {
			t.Fatalf("test '%s': expected nonce %d, got %d", tc.name, tc.nonce, tsr.Nonce)
		}
		// check hash and hashed message
		if tsr.HashAlgorithm != tc.hash {
			t.Fatalf("test '%s': unexpected hash algorithm", tc.name)
		}
		hashedMessage := sha256.Sum256([]byte(testArtifact))
		if !bytes.Equal(tsr.HashedMessage, hashedMessage[:]) {
			t.Fatalf("test '%s': expected hashed messages to be equal: %v %v", tc.name, tsr.HashedMessage, hashedMessage)
		}
		// check time and accuracy
		if tsr.Time.After(time.Now()) {
			t.Fatalf("test '%s': expected time to be set to a previous time", tc.name)
		}
		if tsr.Time.Location() != time.UTC {
			t.Fatalf("test '%s': expected time to be in UTC, got %v", tc.name, tsr.Time.Location())
		}
		duration, _ := time.ParseDuration("1s")
		if tsr.Accuracy != duration {
			t.Fatalf("test '%s': expected 1s accuracy, got %v", tc.name, tsr.Accuracy)
		}
		// check serial number
		if tsr.SerialNumber.Cmp(big.NewInt(0)) == 0 {
			t.Fatalf("test '%s': expected serial number, got 0", tc.name)
		}
		// check ordering and qualified defaults
		if tsr.Qualified {
			t.Fatalf("test '%s': tsr should not be qualified", tc.name)
		}
		if tsr.Ordering {
			t.Fatalf("test '%s': tsr should not be ordered", tc.name)
		}
		// check policy OID default
		if !tsr.Policy.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 2}) {
			t.Fatalf("test '%s': unexpected policy ID", tc.name)
		}
		// check for no extensions
		if len(tsr.Extensions) != 0 {
			t.Fatalf("test '%s': expected 0 extensions, got %d", tc.name, len(tsr.Extensions))
		}
	}
}

func TestGetTimestampResponseWithExtsAndOID(t *testing.T) {
	testArtifact := "blob"
	testNonce := big.NewInt(1234)
	testPolicyOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5}
	oidStr := "1.2.3.4.5"
	includeCerts := true
	hashFunc := crypto.SHA256
	hashName := "sha256"

	opts := ts.RequestOptions{
		Nonce:        testNonce,
		TSAPolicyOID: testPolicyOID,
		Hash:         crypto.SHA256,
	}

	tests := []timestampTestCase{
		{
			name:         "Timestamp Query Request",
			reqMediaType: client.TimestampQueryMediaType,
			reqBytes:     buildTimestampQueryReq(t, []byte(testArtifact), opts),
			nonce:        testNonce,
			policyOID:    testPolicyOID,
		},
		{
			name:         "JSON Request",
			reqMediaType: client.JSONMediaType,
			reqBytes:     buildJSONReq(t, []byte(testArtifact), hashFunc, hashName, includeCerts, testNonce, oidStr),
			nonce:        testNonce,
			policyOID:    testPolicyOID,
		},
	}

	for _, tc := range tests {
		url := createServer(t)

		c, err := client.GetTimestampClient(url, client.WithContentType(tc.reqMediaType))
		if err != nil {
			t.Fatalf("test '%s': unexpected error creating client: %v", tc.name, err)
		}

		// populate additional request parameters for extensions and OID - atypical request structure
		var req *ts.Request
		if tc.reqMediaType == client.TimestampQueryMediaType {
			req, err = ts.ParseRequest(tc.reqBytes)
			if err != nil {
				t.Fatalf("test '%s': unexpected error parsing request: %v", tc.name, err)
			}
		} else {
			req, _, err = api.ParseJSONRequest(tc.reqBytes)
			if err != nil {
				t.Fatalf("test '%s': unexpected error parsing request: %v", tc.name, err)
			}
		}
		req.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{1, 2, 3, 4}}}
		fakePolicyOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5}
		req.TSAPolicyOID = fakePolicyOID
		tsq, err := req.Marshal()
		if err != nil {
			t.Fatalf("test '%s': unexpected error creating request: %v", tc.name, err)
		}

		params := timestamp.NewGetTimestampResponseParams()
		params.SetTimeout(10 * time.Second)
		params.Request = io.NopCloser(bytes.NewReader(tsq))

		var respBytes bytes.Buffer
		clientOption := func(op *runtime.ClientOperation) {
			op.ConsumesMediaTypes = []string{client.TimestampQueryMediaType}
		}
		_, _, err = c.Timestamp.GetTimestampResponse(params, &respBytes, clientOption)
		if err != nil {
			t.Fatalf("test '%s': unexpected error getting timestamp response: %v", tc.name, err)
		}

		tsr, err := ts.ParseResponse(respBytes.Bytes())
		if err != nil {
			t.Fatalf("test '%s': unexpected error parsing response: %v", tc.name, err)
		}

		// check policy OID
		if !tsr.Policy.Equal(fakePolicyOID) {
			t.Fatalf("test '%s': unexpected policy ID", tc.name)
		}
		// check extension is present
		if len(tsr.Extensions) != 1 {
			t.Fatalf("test '%s': expected 1 extension, got %d", tc.name, len(tsr.Extensions))
		}
	}
}

func TestGetTimestampResponseWithNoCertificateOrNonce(t *testing.T) {
	testArtifact := "blob"
	includeCerts := false
	hashFunc := crypto.SHA256
	hashName := "sha256"
	oidStr := "1.2.3.4"

	opts := ts.RequestOptions{
		Certificates: includeCerts,
		Hash:         crypto.SHA256,
	}

	tests := []timestampTestCase{
		{
			name:         "Timestamp Query Request",
			reqMediaType: client.TimestampQueryMediaType,
			reqBytes:     buildTimestampQueryReq(t, []byte(testArtifact), opts),
		},
		{
			name:         "JSON Request",
			reqMediaType: client.JSONMediaType,
			reqBytes:     buildJSONReq(t, []byte(testArtifact), hashFunc, hashName, includeCerts, nil, oidStr),
		},
	}

	for _, tc := range tests {
		url := createServer(t)

		c, err := client.GetTimestampClient(url, client.WithContentType(tc.reqMediaType))
		if err != nil {
			t.Fatalf("test '%s': unexpected error creating client: %v", tc.name, err)
		}

		params := timestamp.NewGetTimestampResponseParams()
		params.SetTimeout(10 * time.Second)
		params.Request = io.NopCloser(bytes.NewReader(tc.reqBytes))

		var respBytes bytes.Buffer
		clientOption := func(op *runtime.ClientOperation) {
			op.ConsumesMediaTypes = []string{tc.reqMediaType}
		}
		_, _, err = c.Timestamp.GetTimestampResponse(params, &respBytes, clientOption)
		if err != nil {
			t.Fatalf("test '%s': unexpected error getting timestamp response: %v", tc.name, err)
		}

		tsr, err := ts.ParseResponse(respBytes.Bytes())
		if err != nil {
			t.Fatalf("test '%s': unexpected error parsing response: %v", tc.name, err)
		}

		// check certificate fields
		if len(tsr.Certificates) != 0 {
			t.Fatalf("test '%s': expected 0 certificates, got %d", tc.name, len(tsr.Certificates))
		}
		if tsr.AddTSACertificate {
			t.Fatalf("test '%s': expected no TSA certificate", tc.name)
		}
		// check nonce
		if tsr.Nonce != nil {
			t.Fatalf("test '%s': expected no nonce, got %d", tc.name, tsr.Nonce)
		}
	}
}

func TestUnsupportedHashAlgorithm(t *testing.T) {
	testArtifact := "blob"
	hashFunc := crypto.SHA1
	hashName := "sha1"

	opts := ts.RequestOptions{
		Hash: crypto.SHA1,
	}

	tests := []timestampTestCase{
		{
			name:         "Timestamp Query Request",
			reqMediaType: client.TimestampQueryMediaType,
			reqBytes:     buildTimestampQueryReq(t, []byte(testArtifact), opts),
		},
		{
			name:         "JSON Request",
			reqMediaType: client.JSONMediaType,
			reqBytes:     buildJSONReq(t, []byte(testArtifact), hashFunc, hashName, false, nil, "1.2.3.4"),
		},
	}

	for _, tc := range tests {
		url := createServer(t)

		c, err := client.GetTimestampClient(url, client.WithContentType(tc.reqMediaType))
		if err != nil {
			t.Fatalf("test '%s': unexpected error creating client: %v", tc.name, err)
		}

		params := timestamp.NewGetTimestampResponseParams()
		params.SetTimeout(10 * time.Second)
		params.Request = io.NopCloser(bytes.NewReader(tc.reqBytes))

		var respBytes bytes.Buffer
		clientOption := func(op *runtime.ClientOperation) {
			op.ConsumesMediaTypes = []string{tc.reqMediaType}
		}
		_, _, err = c.Timestamp.GetTimestampResponse(params, &respBytes, clientOption)
		if err == nil {
			t.Fatalf("test '%s': expected error to occur while parsing request", tc.name)
		}

		if !strings.Contains(err.Error(), api.WeakHashAlgorithmTimestampRequest) {
			t.Fatalf("test '%s': error message should contain message about weak hash algorithm: %v", tc.name, err)
		}
	}
}

func TestInvalidJSONArtifactHashNotBase64Encoded(t *testing.T) {
	jsonReq := api.JSONRequest{
		HashAlgorithm: "sha256",
		ArtifactHash:  "not*base64*encoded",
	}

	marshalled, err := json.Marshal(jsonReq)
	if err != nil {
		t.Fatalf("failed to marshal request")
	}

	url := createServer(t)

	c, err := client.GetTimestampClient(url, client.WithContentType(client.JSONMediaType))
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	params := timestamp.NewGetTimestampResponseParams()
	params.SetTimeout(10 * time.Second)
	params.Request = io.NopCloser(bytes.NewReader(marshalled))

	var respBytes bytes.Buffer
	clientOption := func(op *runtime.ClientOperation) {
		op.ConsumesMediaTypes = []string{client.JSONMediaType}
	}
	_, _, err = c.Timestamp.GetTimestampResponse(params, &respBytes, clientOption)
	if err == nil {
		t.Fatalf("expected error to occur while parsing request")
	}
}
