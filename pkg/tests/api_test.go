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
	"io"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	ts "github.com/digitorus/timestamp"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/timestamp-authority/pkg/client"
	"github.com/sigstore/timestamp-authority/pkg/tests/data"
	"github.com/sigstore/timestamp-authority/pkg/generated/client/timestamp"
	"github.com/sigstore/timestamp-authority/pkg/x509"

	"github.com/go-openapi/runtime"
)

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
	if err := x509.VerifyCertChain(certs, signer); err != nil {
		t.Fatalf("unexpected error verifying cert chain: %v", err)
	}
}

type timestampTestCase struct {
	name         string
	reqMediaType string
	req          []byte
	nonce        *big.Int
}

func buildTimestampQueryReq(t *testing.T, nonce *big.Int) []byte {
	tsq, err := ts.CreateRequest(strings.NewReader("blobblobblobblobblobblobblobblobblob"), &ts.RequestOptions{
		Hash:         crypto.SHA256,
		Certificates: true,
		Nonce:        nonce,
	})
	if err != nil {
		t.Fatalf("unexpected error creating request: %v", err)
	}
	return tsq
}

func readRequestFromFile(t *testing.T, path string) []byte {
	reqBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("unexpected error reading request from file: %v", err)
	}
	return reqBytes
}

func TestGetTimestampResponse(t *testing.T) {
	testNonce := big.NewInt(1234)

	tests := []timestampTestCase{
		{
			name:         "Timestamp Query Request",
			reqMediaType: client.TimestampQueryMediaType,
			req:          buildTimestampQueryReq(t, testNonce),
			nonce:        testNonce,
		},
		{
			name:         "JSON Request",
			reqMediaType: "application/json",
			req:          data.BuildJSONReq(t, strings.NewReader("blobblobblobblobblobblobblobblobblob"), crypto.SHA256, testNonce),
			nonce:        testNonce,
		},
	}

	for _, tc := range tests {
		url := createServer(t)

		c, err := client.GetTimestampClient(url, client.WithContentType(tc.reqMediaType))
		if err != nil {
			t.Fatalf("unexpected error creating client: %v", err)
		}

		params := timestamp.NewGetTimestampResponseParams()
		params.SetTimeout(10 * time.Second)
		params.Request = io.NopCloser(bytes.NewReader(tc.req))

		var respBytes bytes.Buffer
		clientOption := func(op *runtime.ClientOperation) {
			op.ConsumesMediaTypes = []string{tc.reqMediaType}
		}
		_, err = c.Timestamp.GetTimestampResponse(params, &respBytes, clientOption)
		if err != nil {
			t.Fatalf("unexpected error getting timestamp response: %v", err)
		}

		tsr, err := ts.ParseResponse(respBytes.Bytes())
		if err != nil {
			t.Fatalf("unexpected error parsing response: %v", err)
		}

		// check certificate fields
		if len(tsr.Certificates) != 1 {
			t.Fatalf("expected 1 certificate, got %d", len(tsr.Certificates))
		}
		if !tsr.AddTSACertificate {
			t.Fatalf("expected TSA certificate")
		}
		// check nonce
		if tsr.Nonce.Cmp(tc.nonce) != 0 {
			t.Fatalf("expected nonce %d, got %d", tc.nonce, tsr.Nonce)
		}
		// check hash and hashed message
		if tsr.HashAlgorithm != crypto.SHA256 {
			t.Fatalf("unexpected hash algorithm")
		}
		hashedMessage := sha256.Sum256([]byte("blobblobblobblobblobblobblobblobblob"))
		if !bytes.Equal(tsr.HashedMessage, hashedMessage[:]) {
			t.Fatalf("expected hashed messages to be equal: %v %v", tsr.HashedMessage, hashedMessage)
		}
		// check time and accuracy
		if tsr.Time.After(time.Now()) {
			t.Fatalf("expected time to be set to a previous time")
		}
		duration, _ := time.ParseDuration("1s")
		if tsr.Accuracy != duration {
			t.Fatalf("expected 1s accuracy, got %v", tsr.Accuracy)
		}
		// check serial number
		if tsr.SerialNumber.Cmp(big.NewInt(0)) == 0 {
			t.Fatalf("expected serial number, got 0")
		}
		// check ordering and qualified defaults
		if tsr.Qualified {
			t.Fatalf("tsr should not be qualified")
		}
		if tsr.Ordering {
			t.Fatalf("tsr should not be ordered")
		}
		// check policy OID default
		if !tsr.Policy.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 2}) {
			t.Fatalf("unexpected policy ID")
		}
		// check for no extensions
		if len(tsr.Extensions) != 0 {
			t.Fatalf("expected 0 extensions, got %d", len(tsr.Extensions))
		}
	}
}

func TestGetTimestampResponseWithExtsAndOID(t *testing.T) {
	url := createServer(t)

	c, err := client.GetTimestampClient(url, client.WithContentType(client.TimestampQueryMediaType))
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	// create request with nonce and certificate, the typical request structure
	tsNonce := big.NewInt(1234)
	tsq, err := ts.CreateRequest(strings.NewReader("blob"), &ts.RequestOptions{
		Hash:         crypto.SHA256,
		Certificates: true,
		Nonce:        tsNonce,
	})
	if err != nil {
		t.Fatalf("unexpected error creating request: %v", err)
	}
	// populate additional request parameters for extensions and OID - atypical request structure
	req, err := ts.ParseRequest(tsq)
	if err != nil {
		t.Fatalf("unexpected error parsing request: %v", err)
	}
	req.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{1, 2, 3, 4}}}
	fakePolicyOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5}
	req.TSAPolicyOID = fakePolicyOID
	tsq, err = req.Marshal()
	if err != nil {
		t.Fatalf("unexpected error creating request: %v", err)
	}

	params := timestamp.NewGetTimestampResponseParams()
	params.SetTimeout(10 * time.Second)
	params.Request = io.NopCloser(bytes.NewReader(tsq))

	var respBytes bytes.Buffer
	clientOption := func(op *runtime.ClientOperation) {
		op.ConsumesMediaTypes = []string{client.TimestampQueryMediaType}
	}
	_, err = c.Timestamp.GetTimestampResponse(params, &respBytes, clientOption)
	if err != nil {
		t.Fatalf("unexpected error getting timestamp response: %v", err)
	}

	tsr, err := ts.ParseResponse(respBytes.Bytes())
	if err != nil {
		t.Fatalf("unexpected error parsing response: %v", err)
	}

	// check policy OID
	if !tsr.Policy.Equal(fakePolicyOID) {
		t.Fatalf("unexpected policy ID")
	}
	// check extension is present
	if len(tsr.Extensions) != 1 {
		t.Fatalf("expected 1 extension, got %d", len(tsr.Extensions))
	}
}

func TestGetTimestampResponseWithNoCertificateOrNonce(t *testing.T) {
	url := createServer(t)

	c, err := client.GetTimestampClient(url, client.WithContentType(client.TimestampQueryMediaType))
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	tsq, err := ts.CreateRequest(strings.NewReader("blob"), &ts.RequestOptions{
		Hash:         crypto.SHA256,
		Certificates: false,
	})
	if err != nil {
		t.Fatalf("unexpected error creating request: %v", err)
	}

	params := timestamp.NewGetTimestampResponseParams()
	params.SetTimeout(10 * time.Second)
	params.Request = io.NopCloser(bytes.NewReader(tsq))

	var respBytes bytes.Buffer
	clientOption := func(op *runtime.ClientOperation) {
		op.ConsumesMediaTypes = []string{client.TimestampQueryMediaType}
	}
	_, err = c.Timestamp.GetTimestampResponse(params, &respBytes, clientOption)
	if err != nil {
		t.Fatalf("unexpected error getting timestamp response: %v", err)
	}

	tsr, err := ts.ParseResponse(respBytes.Bytes())
	if err != nil {
		t.Fatalf("unexpected error parsing response: %v", err)
	}

	// check certificate fields
	if len(tsr.Certificates) != 0 {
		t.Fatalf("expected 0 certificates, got %d", len(tsr.Certificates))
	}
	if tsr.AddTSACertificate {
		t.Fatalf("expected no TSA certificate")
	}
	// check nonce
	if tsr.Nonce != nil {
		t.Fatalf("expected no nonce, got %d", tsr.Nonce)
	}
}
