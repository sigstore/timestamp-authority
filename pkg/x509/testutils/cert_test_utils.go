// Copyright 2022 The Sigstore Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package testutils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

/*
To use:

rootCert, rootKey, _ := GenerateRootCa()
subCert, subKey, _ := GenerateSubordinateCa(rootCert, rootKey)
leafCert, _, _ := GenerateLeafCert(subCert, subKey)

roots := x509.NewCertPool()
subs := x509.NewCertPool()
roots.AddCert(rootCert)
subs.AddCert(subCert)
opts := x509.VerifyOptions{
	Roots:         roots,
	Intermediates: subs,
	KeyUsages: []x509.ExtKeyUsage{
		x509.ExtKeyUsageTimeStamping,
	},
}
_, err := leafCert.Verify(opts)
*/

func createCertificate(template *x509.Certificate, parent *x509.Certificate, pub interface{}, priv crypto.Signer) (*x509.Certificate, error) {
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func GenerateRootCa() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test TSA Timestamping Root",
			Organization: []string{"local"},
		},
		NotBefore:             time.Now().Add(-10 * time.Minute),
		NotAfter:              time.Now().Add(5 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	cert, err := createCertificate(rootTemplate, rootTemplate, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

func GenerateSubordinateCa(rootTemplate *x509.Certificate, rootPriv crypto.Signer) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	subTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test TSA Timestamping Intermediate",
			Organization: []string{"local"},
		},
		NotBefore:             time.Now().Add(-9 * time.Minute),
		NotAfter:              time.Now().Add(2 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	cert, err := createCertificate(subTemplate, rootTemplate, &priv.PublicKey, rootPriv)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

func GenerateLeafCert(parentTemplate *x509.Certificate, parentPriv crypto.Signer) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	timestampExt, err := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}})
	if err != nil {
		return nil, nil, err
	}

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test TSA Timestamping Leaf",
			Organization: []string{"local"},
		},
		NotBefore: time.Now().Add(-1 * time.Minute),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		IsCA:      false,
		// set EKU to x509.ExtKeyUsageTimeStamping but with a critical bit
		ExtraExtensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 37},
				Critical: true,
				Value:    timestampExt,
			},
		},
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	cert, err := createCertificate(certTemplate, parentTemplate, &priv.PublicKey, parentPriv)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}
