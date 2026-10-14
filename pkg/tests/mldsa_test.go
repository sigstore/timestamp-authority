//
// Copyright 2026 The Sigstore Authors.
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
	"crypto/x509"
	"encoding/asn1"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/pkcs7"
	ts "github.com/digitorus/timestamp"
	"github.com/go-openapi/runtime"
	"github.com/spf13/viper"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/timestamp-authority/v2/pkg/api"
	"github.com/sigstore/timestamp-authority/v2/pkg/client"
	"github.com/sigstore/timestamp-authority/v2/pkg/generated/client/timestamp"
	"github.com/sigstore/timestamp-authority/v2/pkg/verification"
	tsx509 "github.com/sigstore/timestamp-authority/v2/pkg/x509"
	"github.com/sigstore/timestamp-authority/v2/pkg/x509/testutils"
)

func writeFileSignerKeyAndChain(t *testing.T, leafKey crypto.PrivateKey, chain []*x509.Certificate) (keyPath, chainPath, password string) {
	td := t.TempDir()
	password = "password1!"

	der, err := cryptoutils.MarshalPrivateKeyToEncryptedDER(leafKey, cryptoutils.StaticPasswordFunc([]byte(password)))
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := cryptoutils.PEMEncode(cryptoutils.EncryptedSigstorePrivateKeyPEMType, der)
	keyPath = filepath.Join(td, "leaf-key.pem")
	if err := os.WriteFile(keyPath, leafPEM, 0600); err != nil {
		t.Fatal(err)
	}

	chainPEM, err := cryptoutils.MarshalCertificatesToPEM(chain)
	if err != nil {
		t.Fatal(err)
	}
	chainPath = filepath.Join(td, "chain.pem")
	if err := os.WriteFile(chainPath, chainPEM, 0600); err != nil {
		t.Fatal(err)
	}

	return keyPath, chainPath, password
}

func setFileSignerViper(keyPath, chainPath, password, signerHash string) {
	viper.Set("timestamp-signer", "file")
	viper.Set("timestamp-signer-hash", signerHash)
	viper.Set("file-signer-key-path", keyPath)
	viper.Set("file-signer-passwd", password)
	viper.Set("certificate-chain-path", chainPath)
	viper.Set("default-policy-oid", nil)
	viper.Set("accepted-policy-oids", nil)
	viper.Set("allow-custom-extensions", false)
	viper.Set("experimental-enable-pqc", true)
}

func setMLDSAFileSignerViper(t *testing.T, signerHash string) (rootCert, subCert *x509.Certificate) {
	rootCert, rootKey, err := testutils.GenerateMLDSARootCa()
	if err != nil {
		t.Fatal(err)
	}
	subCert, subKey, err := testutils.GenerateMLDSASubordinateCa(rootCert, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, leafKey, err := testutils.GenerateMLDSALeafCert(subCert, subKey)
	if err != nil {
		t.Fatal(err)
	}

	keyPath, chainPath, password := writeFileSignerKeyAndChain(t, leafKey, []*x509.Certificate{leafCert, subCert, rootCert})
	setFileSignerViper(keyPath, chainPath, password, signerHash)

	return rootCert, subCert
}

func timestampSignerDigest(t *testing.T, url string) asn1.ObjectIdentifier {
	c, err := client.GetTimestampClient(url, client.WithContentType(client.TimestampQueryMediaType))
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	tsq, err := ts.CreateRequest(strings.NewReader("blob"), &ts.RequestOptions{Hash: crypto.SHA256})
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
	if _, _, err := c.Timestamp.GetTimestampResponse(params, &respBytes, clientOption); err != nil {
		t.Fatalf("unexpected error getting timestamp response: %v", err)
	}

	tsr, err := ts.ParseResponse(respBytes.Bytes())
	if err != nil {
		t.Fatalf("unexpected error parsing response: %v", err)
	}

	p7, err := pkcs7.Parse(tsr.RawToken)
	if err != nil {
		t.Fatalf("unexpected error parsing SignedData: %v", err)
	}
	if len(p7.Signers) != 1 {
		t.Fatalf("expected 1 signer, got %d", len(p7.Signers))
	}
	return p7.Signers[0].DigestAlgorithm.Algorithm
}

// TestNewAPI_MLDSASignerRequiresSHA512Hash calls api.NewAPI with an ML-DSA
// file signer and a --timestamp-signer-hash other than sha512.
// timestamp-authority must reject the mismatch at startup.
func TestNewAPI_MLDSASignerRequiresSHA512Hash(t *testing.T) {
	tests := []string{"sha256", "sha384"}
	for _, hash := range tests {
		t.Run(hash, func(t *testing.T) {
			setMLDSAFileSignerViper(t, hash)

			_, err := api.NewAPI()
			if err == nil || !strings.Contains(err.Error(), "ML-DSA signers require --timestamp-signer-hash=sha512") {
				t.Fatalf("expected ML-DSA signer with %s hash to be rejected at startup, got: %v", hash, err)
			}
		})
	}
}

// TestNewAPI_MLDSARequiresExperimentalPQCFlag calls api.NewAPI with an ML-DSA
// file signer and an all-ML-DSA certificate chain. Startup must fail unless
// --experimental-enable-pqc is set.
func TestNewAPI_MLDSARequiresExperimentalPQCFlag(t *testing.T) {
	setMLDSAFileSignerViper(t, "sha512")

	viper.Set("experimental-enable-pqc", false)
	if _, err := api.NewAPI(); err == nil || !strings.Contains(err.Error(), "ML-DSA signers require --experimental-enable-pqc") {
		t.Fatalf("expected ML-DSA signer to be rejected at startup without --experimental-enable-pqc, got: %v", err)
	}

	viper.Set("experimental-enable-pqc", true)
	if _, err := api.NewAPI(); err != nil {
		t.Fatalf("unexpected error starting ML-DSA signer with --experimental-enable-pqc set: %v", err)
	}
}

// TestNewAPI_PolicyOIDMustMatchSignerKeyType calls api.NewAPI with the two
// well-known sigstore policy OIDs against a signer whose key type does not
// match. Both must be rejected at startup. A custom OID bypasses the check
// regardless of the signer key type.
func TestNewAPI_PolicyOIDMustMatchSignerKeyType(t *testing.T) {
	t.Run("non-PQC OID with ML-DSA signer", func(t *testing.T) {
		setMLDSAFileSignerViper(t, "sha512")
		viper.Set("accepted-policy-oids", []string{tsx509.PolicyOID.String()})
		viper.Set("default-policy-oid", tsx509.PolicyOID.String())

		if _, err := api.NewAPI(); err == nil || !strings.Contains(err.Error(), "does not support ML-DSA signers") {
			t.Fatalf("expected the non-PQC policy OID to be rejected for an ML-DSA signer, got: %v", err)
		}
	})

	t.Run("PQC OID with classical signer", func(t *testing.T) {
		rootCert, rootKey, err := testutils.GenerateRootCa()
		if err != nil {
			t.Fatal(err)
		}
		leafCert, leafKey, err := testutils.GenerateLeafCert(rootCert, rootKey)
		if err != nil {
			t.Fatal(err)
		}

		keyPath, chainPath, password := writeFileSignerKeyAndChain(t, leafKey, []*x509.Certificate{leafCert, rootCert})
		setFileSignerViper(keyPath, chainPath, password, "sha256")
		viper.Set("experimental-enable-pqc", false)
		viper.Set("accepted-policy-oids", []string{tsx509.PolicyOIDPQC.String()})
		viper.Set("default-policy-oid", tsx509.PolicyOIDPQC.String())

		if _, err := api.NewAPI(); err == nil || !strings.Contains(err.Error(), "requires an ML-DSA signer") {
			t.Fatalf("expected the PQC policy OID to be rejected for a classical signer, got: %v", err)
		}
	})

	t.Run("custom OID bypasses the check", func(t *testing.T) {
		setMLDSAFileSignerViper(t, "sha512")
		viper.Set("accepted-policy-oids", []string{"1.2.3.4.5"})
		viper.Set("default-policy-oid", "1.2.3.4.5")

		if _, err := api.NewAPI(); err != nil {
			t.Fatalf("unexpected error starting an ML-DSA signer with a custom policy OID: %v", err)
		}
	})
}

// TestNewAPI_MLDSAChainMustBeAllMLDSA calls api.NewAPI with an ML-DSA
// file signer whose certificate chain mixes ML-DSA and non-ML-DSA (ECDSA)
// public keys. The chain must be rejected at startup.
func TestNewAPI_MLDSAChainMustBeAllMLDSA(t *testing.T) {
	rootCert, rootKey, err := testutils.GenerateRootCa()
	if err != nil {
		t.Fatal(err)
	}
	subCert, subKey, err := testutils.GenerateSubordinateCa(rootCert, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, leafKey, err := testutils.GenerateMLDSALeafCert(subCert, subKey)
	if err != nil {
		t.Fatal(err)
	}

	keyPath, chainPath, password := writeFileSignerKeyAndChain(t, leafKey, []*x509.Certificate{leafCert, subCert, rootCert})
	setFileSignerViper(keyPath, chainPath, password, "sha512")

	_, err = api.NewAPI()
	if err == nil || !strings.Contains(err.Error(), "must not mix ML-DSA") {
		t.Fatalf("expected a chain mixing ML-DSA and non-ML-DSA public keys to be rejected at startup, got: %v", err)
	}
}

// TestGetTimestampResponse_MLDSASignerRoundTrip tests the full TSA HTTP
// API backed by a file signer using an ML-DSA key and an all ML-DSA
// certificate chain, configured with sha512 as the hash. It confirms a
// timestamp can be requested, the returned	SignerInfo digest is SHA-512,
// and that the response verifies successfully.
func TestGetTimestampResponse_MLDSASignerRoundTrip(t *testing.T) {
	var rootCert, subCert *x509.Certificate
	url := createServer(t, func() {
		rootCert, subCert = setMLDSAFileSignerViper(t, "sha512")
	})

	digestOID := timestampSignerDigest(t, url)
	if !digestOID.Equal(pkcs7.OIDDigestAlgorithmSHA512) {
		t.Fatalf("expected ML-DSA SignerInfo digest algorithm to be SHA-512, got %v", digestOID)
	}

	c, err := client.GetTimestampClient(url, client.WithContentType(client.TimestampQueryMediaType))
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	message := "blob"
	tsq, err := ts.CreateRequest(strings.NewReader(message), &ts.RequestOptions{Hash: crypto.SHA256, Certificates: true})
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
	if _, _, err := c.Timestamp.GetTimestampResponse(params, &respBytes, clientOption); err != nil {
		t.Fatalf("unexpected error getting timestamp response: %v", err)
	}

	tsr, err := ts.ParseResponse(respBytes.Bytes())
	if err != nil {
		t.Fatalf("unexpected error parsing response: %v", err)
	}
	if !tsr.Policy.Equal(tsx509.PolicyOIDPQC) {
		t.Fatalf("expected ML-DSA signer to default to the PQC policy OID %s, got %s", tsx509.PolicyOIDPQC, tsr.Policy)
	}

	if _, err := verification.VerifyTimestampResponse(respBytes.Bytes(), strings.NewReader(message), verification.VerifyOpts{
		Roots:         []*x509.Certificate{rootCert},
		Intermediates: []*x509.Certificate{subCert},
	}); err != nil {
		t.Fatalf("unexpected error verifying ML-DSA-signed timestamp response: %v", err)
	}
}
