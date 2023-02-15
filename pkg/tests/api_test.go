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
	"strings"
	"testing"
	"time"

	ts "github.com/digitorus/timestamp"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/timestamp-authority/pkg/client"
	"github.com/sigstore/timestamp-authority/pkg/generated/client/timestamp"
	"github.com/sigstore/timestamp-authority/pkg/x509"
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

func TestGetTimestampResponse(t *testing.T) {
	type test struct {
		name            string
		policyOID       []int
		extensions      []pkix.Extension
		nonce           *big.Int
		addCertificates bool
	}

	tests := []test{
		{
			name:            "Expect default policy OID and no extensions",
			policyOID:       nil,
			extensions:      nil,
			nonce:           big.NewInt(1234),
			addCertificates: true,
		},
		{
			name:            "Expect custom policy OID and extensions",
			policyOID:       asn1.ObjectIdentifier{1, 2, 3, 4, 5},
			extensions:      []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{1, 2, 3, 4}}},
			nonce:           big.NewInt(1234),
			addCertificates: true,
		},
		{
			name:            "Expect no nonce or TSA certificate",
			policyOID:       asn1.ObjectIdentifier{1, 2, 3, 4, 5},
			extensions:      []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{1, 2, 3, 4}}},
			addCertificates: false,
		},
	}

	for _, tc := range tests {
		url := createServer(t)

		c, err := client.GetTimestampClient(url)
		if err != nil {
			t.Fatalf("unexpected error creating client: %v", err)
		}

		// create request with nonce and certificate, the typical request structure
		tsq, err := ts.CreateRequest(strings.NewReader("blobblobblobblobblobblobblobblobblob"), &ts.RequestOptions{
			Hash:         crypto.SHA256,
			Certificates: tc.addCertificates,
			Nonce:        tc.nonce,
		})
		if err != nil {
			t.Fatalf("unexpected error creating request: %v", err)
		}

		params := timestamp.NewGetTimestampResponseParams()
		params.SetTimeout(10 * time.Second)
		params.Request = io.NopCloser(bytes.NewReader(tsq))

		var respBytes bytes.Buffer
		_, err = c.Timestamp.GetTimestampResponse(params, &respBytes)
		if err != nil {
			t.Fatalf("unexpected error getting timestamp response: %v", err)
		}

		tsr, err := ts.ParseResponse(respBytes.Bytes())
		if err != nil {
			t.Fatalf("unexpected error parsing response: %v", err)
		}

		// if tc.extensions != nil {
		// 	tsr.ExtraExtensions = tc.extensions
		// }
		// if tc.oidPolicy != nil {
		// 	tsr.TSAPolicyOID = tc.policyOID
		// }

		// check certificate fields
		if !tc.addCertificates {
			if tsr.AddTSACertificate {
				t.Fatalf("expected no TSA certificate")
			}
			if len(tsr.Certificates) != 0 {
				t.Fatalf("expected 0 certificates, got %d", len(tsr.Certificates))
			}
		}

		if tc.addCertificates {
			if !tsr.AddTSACertificate {
				t.Fatalf("expected TSA certificate")
			}
			if len(tsr.Certificates) != 0 {
				t.Fatalf("expected 1 certificate, got %d", len(tsr.Certificates))
			}
		}

		// check nonce
		if tc.nonce == nil && tsr.Nonce.Cmp(tc.nonce) != 0 {
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
		// check policy OID
		if (tc.policyOID == nil && !tsr.Policy.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 2})) || (tc.policyOID != nil && !tsr.Policy.Equal(tc.policyOID)) {
			t.Fatalf("unexpected policy ID")
		}
		// check extension is present
		if (tc.extensions == nil || len(tsr.Extensions) != 0) || (tc.extensions != nil || len(tsr.Extensions) != len(tc.extensions)) {
			t.Fatalf("expected 1 extension, got %d", len(tsr.Extensions))
		}
	}
}
