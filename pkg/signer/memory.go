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
	tsx509 "github.com/sigstore/timestamp-authority/v2/pkg/x509"
)

// NewTimestampingCertWithChain generates an in-memory certificate chain.
func NewTimestampingCertWithChain(signer crypto.Signer) ([]*x509.Certificate, error) {
	now := time.Now()

	// generate root
	rootPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating in-memory root key")
	}
	sn, err := cryptoutils.GenerateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("generating root serial number: %w", err)
	}
	rootCA := &x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			CommonName:   "Test TSA Root",
			Organization: []string{"local"},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootCACertDER, err := x509.CreateCertificate(rand.Reader, rootCA, rootCA, rootPriv.Public(), rootPriv)
	if err != nil {
		return nil, fmt.Errorf("creating self-signed root CA: %w", err)
	}
	rootCACert, err := x509.ParseCertificate(rootCACertDER)
	if err != nil {
		return nil, fmt.Errorf("parsing root CA certificate: %w", err)
	}

	// generate subordinate
	sn, err = cryptoutils.GenerateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("generating subordinate serial number: %w", err)
	}
	subPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating in-memory subordinate key")
	}
	subCA := &x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			CommonName:   "Test TSA Intermediate",
			Organization: []string{"local"},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	subCACertDER, err := x509.CreateCertificate(rand.Reader, subCA, rootCACert, subPriv.Public(), rootPriv)
	if err != nil {
		return nil, fmt.Errorf("creating self-signed subordinate CA: %w", err)
	}
	subCACert, err := x509.ParseCertificate(subCACertDER)
	if err != nil {
		return nil, fmt.Errorf("parsing subordinate CA certificate: %w", err)
	}

	// generate leaf
	sn, err = cryptoutils.GenerateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("generating leaf serial number: %w", err)
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
		NotBefore:    now.Add(-3 * time.Minute),
		NotAfter:     now.AddDate(9, 0, 0),
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
	certDER, err := x509.CreateCertificate(rand.Reader, cert, subCACert, signer.Public(), subPriv)
	if err != nil {
		return nil, errors.Wrap(err, "creating tsa certificate")
	}
	tsaCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	// Verify and return the certificate chain
	root := x509.NewCertPool()
	root.AddCert(rootCACert)
	intermediate := x509.NewCertPool()
	intermediate.AddCert(subCACert)
	verifyOptions := x509.VerifyOptions{
		Roots:         root,
		Intermediates: intermediate,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	if _, err = tsaCert.Verify(verifyOptions); err != nil {
		return nil, err
	}

	return []*x509.Certificate{tsaCert, subCACert, rootCACert}, nil
}
