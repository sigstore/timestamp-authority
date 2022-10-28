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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"time"

	"github.com/pkg/errors"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	tsx509 "github.com/sigstore/timestamp-authority/pkg/x509"
)

// NewTimestampingCertWithChain generates an in-memory certificate chain.
func NewTimestampingCertWithChain(ctx context.Context, signer crypto.Signer) ([]*x509.Certificate, error) {
	rootPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating in-memory root key")
	}
	sn, err := cryptoutils.GenerateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("generating serial number: %w", err)
	}
	ca := &x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			CommonName:   "Test TSA Root",
			Organization: []string{"local"},
		},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, ca, ca, rootPriv.Public(), rootPriv)
	if err != nil {
		return nil, fmt.Errorf("creating self-signed CA: %w", err)
	}

	sn, err = cryptoutils.GenerateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("generating serial number: %w", err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("parsing CA certificate: %w", err)
	}

	timestampExt, err := asn1.Marshal([]asn1.ObjectIdentifier{tsx509.EKUTimestampingOID})
	if err != nil {
		return nil, err
	}

	skid, err := cryptoutils.SKID(signer.Public())
	if err != nil {
		return nil, err
	}

	cert := &x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			CommonName:   "Test TSA Timestamping",
			Organization: []string{"local"},
		},
		SubjectKeyId: skid,
		NotBefore:    time.Now().Add(-3 * time.Minute),
		NotAfter:     time.Now().AddDate(9, 0, 0),
		IsCA:         false,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		// set EKU to x509.ExtKeyUsageTimeStamping but with a critical bit
		ExtraExtensions: []pkix.Extension{
			{
				Id:       tsx509.EKUOID,
				Critical: true,
				Value:    timestampExt,
			},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, cert, caCert, signer.Public(), rootPriv)
	if err != nil {
		return nil, errors.Wrap(err, "creating tsa certificate")
	}
	tsaCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	// Verify and return the certificate chain
	root := x509.NewCertPool()
	root.AddCert(caCert)
	verifyOptions := x509.VerifyOptions{
		Roots:     root,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	if _, err = tsaCert.Verify(verifyOptions); err != nil {
		return nil, err
	}

	return []*x509.Certificate{tsaCert, caCert}, nil
}
