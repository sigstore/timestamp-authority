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

package x509

import (
	"crypto/x509"
	"strings"
	"testing"

	"github.com/sigstore/timestamp-authority/v2/pkg/x509/testutils"
)

func TestVerifyCertChain(t *testing.T) {
	// success with leaf, intermediate, and root
	rootCert, rootKey, _ := testutils.GenerateRootCa()
	subCert, subKey, _ := testutils.GenerateSubordinateCa(rootCert, rootKey)
	leafCert, leafKey, _ := testutils.GenerateLeafCert(subCert, subKey)
	if err := VerifyCertChain([]*x509.Certificate{leafCert, subCert, rootCert}, leafKey, true); err != nil {
		t.Fatalf("unexpected failure verifying certificate chain: %v", err)
	}

	// success with leaf and root
	leafFromRootCert, leafFromRootKey, _ := testutils.GenerateLeafCert(rootCert, rootKey)
	if err := VerifyCertChain([]*x509.Certificate{leafFromRootCert, rootCert}, leafFromRootKey, true); err != nil {
		t.Fatalf("unexpected failure verifying certificate chain: %v", err)
	}

	// failure: not enough certificates
	if err := VerifyCertChain([]*x509.Certificate{leafCert}, leafKey, true); err == nil || !strings.Contains(err.Error(), "must contain at least two") {
		t.Fatalf("expected failure verifying certificate chain: %v", err)
	}

	// failure: no certificates passed
	if err := VerifyCertChain([]*x509.Certificate{}, leafKey, true); err == nil || !strings.Contains(err.Error(), "certificate chain must contain a leaf certificate") {
		t.Fatalf("expected failure verifying certificate chain: %v", err)
	}

	// failure: nil signer
	if err := VerifyCertChain([]*x509.Certificate{leafFromRootCert, rootCert}, nil, true); err == nil || !strings.Contains(err.Error(), "signer must not be nil") {
		t.Fatalf("expected failure verifying certificate chain: %v", err)
	}

	// failure: mismatched public key
	if err := VerifyCertChain([]*x509.Certificate{leafCert, subCert, rootCert}, leafFromRootKey, true); err == nil || !strings.Contains(err.Error(), "public keys are not equal") {
		t.Fatalf("expected failure verifying certificate chain: %v", err)
	}
}
