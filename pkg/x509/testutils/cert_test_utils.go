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
	"crypto/mldsa"
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

func createCertificate(template *x509.Certificate, parent *x509.Certificate, pub any, priv crypto.Signer) (*x509.Certificate, error) {
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

func ecdsaKeyGen() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func mldsaKeyGen() (*mldsa.PrivateKey, error) {
	return mldsa.GenerateKey(mldsa.MLDSA65())
}

func generateRootCa[K crypto.Signer](commonName string, keyGen func() (K, error)) (*x509.Certificate, K, error) {
	var zero K

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"local"},
		},
		NotBefore:             time.Now().Add(-10 * time.Minute),
		NotAfter:              time.Now().Add(5 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	priv, err := keyGen()
	if err != nil {
		return nil, zero, err
	}

	cert, err := createCertificate(rootTemplate, rootTemplate, priv.Public(), priv)
	if err != nil {
		return nil, zero, err
	}

	return cert, priv, nil
}

func GenerateRootCa() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	return generateRootCa("Test TSA Timestamping Root", ecdsaKeyGen)
}

func GenerateMLDSARootCa() (*x509.Certificate, *mldsa.PrivateKey, error) {
	return generateRootCa("Test TSA Timestamping Root (ML-DSA)", mldsaKeyGen)
}

func generateSubordinateCa[K crypto.Signer](rootTemplate *x509.Certificate, rootPriv crypto.Signer, commonName string, keyGen func() (K, error)) (*x509.Certificate, K, error) {
	var zero K

	subTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"local"},
		},
		NotBefore:             time.Now().Add(-9 * time.Minute),
		NotAfter:              time.Now().Add(2 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	priv, err := keyGen()
	if err != nil {
		return nil, zero, err
	}

	cert, err := createCertificate(subTemplate, rootTemplate, priv.Public(), rootPriv)
	if err != nil {
		return nil, zero, err
	}

	return cert, priv, nil
}

func GenerateSubordinateCa(rootTemplate *x509.Certificate, rootPriv crypto.Signer) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	return generateSubordinateCa(rootTemplate, rootPriv, "Test TSA Timestamping Intermediate", ecdsaKeyGen)
}

func GenerateMLDSASubordinateCa(rootTemplate *x509.Certificate, rootPriv crypto.Signer) (*x509.Certificate, *mldsa.PrivateKey, error) {
	return generateSubordinateCa(rootTemplate, rootPriv, "Test TSA Timestamping Intermediate (ML-DSA)", mldsaKeyGen)
}

func generateLeafCert[K crypto.Signer](parentTemplate *x509.Certificate, parentPriv crypto.Signer, commonName string, keyGen func() (K, error)) (*x509.Certificate, K, error) {
	var zero K

	timestampExt, err := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}})
	if err != nil {
		return nil, zero, err
	}

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   commonName,
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

	priv, err := keyGen()
	if err != nil {
		return nil, zero, err
	}

	cert, err := createCertificate(certTemplate, parentTemplate, priv.Public(), parentPriv)
	if err != nil {
		return nil, zero, err
	}

	return cert, priv, nil
}

func GenerateLeafCert(parentTemplate *x509.Certificate, parentPriv crypto.Signer) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	return generateLeafCert(parentTemplate, parentPriv, "Test TSA Timestamping Leaf", ecdsaKeyGen)
}

func GenerateMLDSALeafCert(parentTemplate *x509.Certificate, parentPriv crypto.Signer) (*x509.Certificate, *mldsa.PrivateKey, error) {
	return generateLeafCert(parentTemplate, parentPriv, "Test TSA Timestamping Leaf (ML-DSA)", mldsaKeyGen)
}
