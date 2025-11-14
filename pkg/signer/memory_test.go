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

package signer

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"github.com/sigstore/timestamp-authority/v2/pkg/x509"
)

func TestNewTimestampingCertWithChain(t *testing.T) {
	ctx := context.Background()

	signer, err := NewCryptoSigner(ctx, crypto.Hash(0), "memory", "", "", "", "", "", "")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	payload := []byte("payload")
	h := sha256.Sum256(payload)

	sig, err := signer.Sign(rand.Reader, h[:], nil)
	if err != nil {
		t.Fatalf("signing payload: %v", err)
	}
	// create and verify the certificate chain
	certChain, err := NewTimestampingCertWithChain(signer)
	if err != nil {
		t.Fatalf("generating timestamping cert: %v", err)
	}
	if len(certChain) != 3 {
		t.Fatalf("expected 3 certificates in chain, got %d", len(certChain))
	}

	// verify that certificate can verify signature
	pkCert := certChain[0].PublicKey
	verifier, err := signature.LoadVerifier(pkCert, crypto.SHA256)
	if err != nil {
		t.Fatalf("initializing verifier: %v", err)
	}
	if err := verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(payload), options.WithContext(ctx)); err != nil {
		t.Fatalf("failed to verify signature: %v", err)
	}

	// verify that VerifyCertChain will successfully verify the chain
	if err := x509.VerifyCertChain(certChain, signer, true); err != nil {
		t.Fatalf("failed to verify certificate chain: %v", err)
	}
}
