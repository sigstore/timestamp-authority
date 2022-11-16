//
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

package verification

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
)

type VerificationOpts struct {
	Oid            asn1.ObjectIdentifier
	TsaCertificate *x509.Certificate
	Intermediates  []*x509.Certificate
	Roots          []*x509.Certificate
	Nonce          *big.Int
	Subject        string
}

func NewVerificationOpts(tsr []byte, artifact io.Reader, pemCerts []byte) (VerificationOpts, error) {
	ts, err := timestamp.ParseResponse(tsr)
	if err != nil {
		pe := timestamp.ParseError("")
		if errors.As(err, &pe) {
			return VerificationOpts{}, fmt.Errorf("timestamp response is not valid: %w", err)
		}
		return VerificationOpts{}, fmt.Errorf("error parsing response into Timestamp: %w", err)
	}

	intermediateCerts := []*x509.Certificate{}
	rootCerts := []*x509.Certificate{}
	for len(pemCerts) > 0 {
		block, rest := pem.Decode(pemCerts)
		// if there is nothing left, we have found the last block
		// which should be the root
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return VerificationOpts{}, fmt.Errorf("failed to parse certificate")
		}
		if rest == nil {
			rootCerts = append(rootCerts, cert)
		} else {
			intermediateCerts = append(intermediateCerts, cert)
		}
		pemCerts = rest
	}

	opts := VerificationOpts{}
	opts.Oid = ts.Policy
	opts.TsaCertificate = ts.Certificates[0]
	opts.Intermediates = intermediateCerts
	opts.Roots = rootCerts
	opts.Nonce = ts.Nonce
	opts.Subject = ts.Certificates[0].Subject.String()

	return opts, nil
}

func createCertPool(certBytes []byte) (*x509.CertPool, error) {
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(certBytes); !ok {
		return nil, fmt.Errorf("failed to append certs to cert pool")
	}
	return certPool, nil
}

// Verify the TSR's certificate identifier matches a provided TSA certificate
func VerifyESSCertID(tsrBytes []byte, tsaCert *x509.Certificate) (bool, error) {
	// Verify the status of the TSR does not contain an error
	// handled by the timestamp.ParseResponse function
	ts, err := timestamp.ParseResponse(tsrBytes)
	if err != nil {
		pe := timestamp.ParseError("")
		if errors.As(err, &pe) {
			return false, fmt.Errorf("timestamp response is not valid: %w", err)
		}
		return false, fmt.Errorf("error parsing response into Timestamp: %w", err)
	}

	return ts.Certificates[0].Issuer.String() == tsaCert.Issuer.String() && ts.Certificates[0].SerialNumber == tsaCert.SerialNumber, nil
}

// Verify the leaf certificate's subject and/or subject alternative name matches a provided subject
func VerifyLeafCertSubject(opts VerificationOpts, subject pkix.Name) bool {
	return opts.TsaCertificate.Subject.String() == subject.String()
}

// Verify the TSA certificate using a CA certificate chain
func VerifyTSACertWithChain(opts VerificationOpts, certChain []x509.Certificate) bool {
	opts.TsaCertificate.Equal(&certChain[0])
	return false
}

// Verify the TSA certificate and the intermediates (called "EKU chaining") all
// have the extended key usage set to only extended key usage
func VerifyExtendedKeyUsage(opts VerificationOpts) bool {
	leafCert := opts.TsaCertificate
	if len(leafCert.ExtKeyUsage) != 1 {
		return false
	}
	return leafCert.ExtKeyUsage[0] == x509.ExtKeyUsageTimeStamping

	for _, cert := range opts.Intermediates {
		if len(cert.ExtKeyUsage) != 1 {
			return false
		}
		return cert.ExtKeyUsage[0] == x509.ExtKeyUsageTimeStamping
	}
	return true
}

// If embedded in the TSR, verify the TSR's leaf certificate matches a provided TSA certificate
func VerifyEmbeddedLeafCert(opts VerificationOpts, tsaCert *x509.Certificate) (bool, error) {
	if opts.TsaCertificate != nil {
		leafCert := opts.TsaCertificate
		return leafCert.Equal(tsaCert), nil
	}
	return true, nil
}

// Verify the signature of the TSR using the public key in the leaf certificate
// func VerifyTSRSignature(data []byte, ts timestamp.Timestamp, opts VerificationOpts) bool {
// 	leafCert := opts.TsaCertificate
// 	signatureAlgo := x509.SignatureAlgorithm
// 	err := leafCert.CheckSignature(ts.HashAlgorithm, data, ts.HashedMessage)
// 	if err != nil {
// 		return false
// 	}
// 	return true
// }

// Verify the OID of the TSR matches an expected OID
func VerifyOID(oid []int, opts VerificationOpts) bool {
	responseOid := opts.Oid
	if len(oid) != len(responseOid) {
		return false
	}
	for i, v := range oid {
		if v != responseOid[i] {
			return false
		}
	}
	return true
}

// Verify the nonce - Mostly important for when the response is first returned
func VerifyNonce(requestNonce *big.Int, opts VerificationOpts) bool {
	return opts.Nonce.Cmp(requestNonce) == 0
}

// VerifyTimestampResponse the timestamp response using a timestamp certificate chain.
func VerifyTimestampResponse(tsrBytes []byte, artifact io.Reader, certPool *x509.CertPool) error {
	// Verify the status of the TSR does not contain an error
	// handled by the timestamp.ParseResponse function
	ts, err := timestamp.ParseResponse(tsrBytes)
	if err != nil {
		pe := timestamp.ParseError("")
		if errors.As(err, &pe) {
			return fmt.Errorf("timestamp response is not valid: %w", err)
		}
		return fmt.Errorf("error parsing response into Timestamp: %w", err)
	}

	// verify the timestamp response signature using the provided certificate pool
	err = verifyTSRWithChain(ts, certPool)
	if err != nil {
		return err
	}

	// verify the hash in the timestamp response matches the artifact hash
	return verifyHashedMessages(ts.HashAlgorithm.New(), ts.HashedMessage, artifact)
}

func verifyTSRWithChain(ts *timestamp.Timestamp, certPool *x509.CertPool) error {
	p7Message, err := pkcs7.Parse(ts.RawToken)
	if err != nil {
		return fmt.Errorf("error parsing hashed message: %w", err)
	}

	err = p7Message.VerifyWithChain(certPool)
	if err != nil {
		return fmt.Errorf("error while verifying with chain: %w", err)
	}

	return nil
}

// Verify that the TSR's hashed message matches the digest of the artifact to be timestamped
func verifyHashedMessages(hashAlg hash.Hash, hashedMessage []byte, artifactReader io.Reader) error {
	h := hashAlg
	if _, err := io.Copy(h, artifactReader); err != nil {
		return fmt.Errorf("failed to create hash %w", err)
	}
	localHashedMsg := h.Sum(nil)

	if !bytes.Equal(localHashedMsg, hashedMessage) {
		return fmt.Errorf("hashed messages don't match")
	}

	return nil
}
