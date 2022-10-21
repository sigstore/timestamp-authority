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
	"encoding/asn1"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ts "github.com/digitorus/timestamp"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/timestamp-authority/pkg/client"
	"github.com/sigstore/timestamp-authority/pkg/generated/client/timestamp"
	"github.com/sigstore/timestamp-authority/pkg/server"
	"github.com/sigstore/timestamp-authority/pkg/x509"
	"github.com/spf13/viper"
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
	url := createServer(t)

	c, err := client.GetTimestampClient(url)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	tsNonce := big.NewInt(1234)
	tsq, err := ts.CreateRequest(strings.NewReader("blob"), &ts.RequestOptions{
		Hash:         crypto.SHA256,
		Certificates: true,
		Nonce:        tsNonce,
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
		t.Fatalf("unexpected error getting timestamp chain: %v", err)
	}

	tsr, err := ts.ParseResponse(respBytes.Bytes())
	if err != nil {
		t.Fatalf("unexpected error parsing response: %v", err)
	}

	if len(tsr.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(tsr.Certificates))
	}
	if !tsr.AddTSACertificate {
		t.Fatalf("expected TSA certificate")
	}
	if tsr.Nonce.Cmp(tsNonce) != 0 {
		t.Fatalf("expected nonce %d, got %d", tsNonce, tsr.Nonce)
	}
	if tsr.HashAlgorithm != crypto.SHA256 {
		t.Fatalf("unexpected hash algorithm")
	}
	if tsr.Accuracy <= 0 {
		t.Fatalf("expected greater than zero accurary, got %v", tsr.Accuracy)
	}
	if tsr.SerialNumber.Cmp(big.NewInt(0)) == 0 {
		t.Fatalf("expected serial number, got 0")
	}
	if tsr.Qualified {
		t.Fatalf("tsr should not be qualified")
	}
	if !tsr.Policy.Equal(asn1.ObjectIdentifier{0, 4, 0, 2023, 1, 1}) {
		t.Fatalf("unexpected policy ID")
	}
}

func createServer(t *testing.T) string {
	viper.Set("timestamp-signer", "memory")
	// unused port
	apiServer := server.NewRestAPIServer("localhost", 0, []string{"http"}, 10*time.Second, 10*time.Second)
	server := httptest.NewServer(apiServer.GetHandler())
	t.Cleanup(server.Close)

	// verify the server's health
	response, err := http.Get(server.URL + "/ping")
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("unexpected error starting up server - status code: %d, err: %v", response.StatusCode, err)
	}

	return server.URL
}
