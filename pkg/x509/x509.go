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
	"crypto"
	"crypto/x509"
	"errors"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// VerifyCertChain verifies that the certificate chain is valid for issuing
// timestamping certificates. The chain should start with a leaf certificate,
// followed by any number of intermediates, and end with the root certificate.
func VerifyCertChain(certs []*x509.Certificate, signer crypto.Signer) error {
	// chain must contain at least one CA certificate and a leaf certificate
	if len(certs) < 2 {
		return errors.New("certificate chain must contain at least two certificates")
	}

	roots := x509.NewCertPool()
	roots.AddCert(certs[len(certs)-1])

	intermediates := x509.NewCertPool()
	if len(certs) > 2 {
		for _, intermediate := range certs[1 : len(certs)-1] {
			intermediates.AddCert(intermediate)
		}
	}

	// Verify the certificate chain
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageTimeStamping,
		},
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}

	// Verify that all certificates but the leaf are CA certificates
	for _, c := range certs[1:] {
		if !c.IsCA {
			return errors.New("certificate is not a CA certificate")
		}
	}

	// If the chain contains intermediates, verify that the extended key
	// usage includes the extended key usage timestamping for EKU chaining
	if len(certs) > 2 {
		for _, c := range certs[1 : len(certs)-1] {
			var hasExtKeyUsageTimeStamping bool
			for _, extKeyUsage := range c.ExtKeyUsage {
				if extKeyUsage == x509.ExtKeyUsageTimeStamping {
					hasExtKeyUsageTimeStamping = true
					break
				}
			}
			if !hasExtKeyUsageTimeStamping {
				return errors.New(`certificate must have extended key usage timestamping set to sign timestamping certificates`)
			}
		}
	}

	// Verify the signer's public key matches the leaf certificate
	if err := cryptoutils.EqualKeys(certs[0].PublicKey, signer.Public()); err != nil {
		return err
	}

	// Verify the key's strength
	if err := cryptoutils.ValidatePubKey(signer.Public()); err != nil {
		return err
	}

	return nil
}
