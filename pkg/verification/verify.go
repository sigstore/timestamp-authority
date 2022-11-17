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
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"hash"
	"io"
	"math/big"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
	"github.com/pkg/errors"
)

type VerifyOpts struct {
	Oid            asn1.ObjectIdentifier
	TsaCertificate *x509.Certificate
	Intermediates  []*x509.Certificate
	Roots          []*x509.Certificate
	Nonce          *big.Int
	Subject        string
	HashAlgorithm  hash.Hash
	HashedMessage  []byte
}

func NewVerificationOpts(ts timestamp.Timestamp, artifact io.Reader, pemCerts []byte) (VerifyOpts, error) {
	intermediateCerts := []*x509.Certificate{}
	rootCerts := []*x509.Certificate{}
	for len(pemCerts) > 0 {
		block, rest := pem.Decode(pemCerts)
		// if there is nothing left, we have found the last block
		// which should be the root
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return VerifyOpts{}, fmt.Errorf("failed to parse certificate")
		}
		if rest == nil {
			rootCerts = append(rootCerts, cert)
		} else {
			intermediateCerts = append(intermediateCerts, cert)
		}
		pemCerts = rest
	}

	opts := VerifyOpts{}
	opts.Oid = ts.Policy
	opts.TsaCertificate = ts.Certificates[0]
	opts.Intermediates = intermediateCerts
	opts.Roots = rootCerts
	opts.Nonce = ts.Nonce
	opts.Subject = ts.Certificates[0].Subject.String()
	opts.HashAlgorithm = ts.HashAlgorithm.New()
	opts.HashedMessage = ts.HashedMessage

	return opts, nil
}

// Verify the TSR's certificate identifier matches a provided TSA certificate
func VerifyESSCertID(tsaCert *x509.Certificate, opt VerifyOpts) error {
	errMessage := ""

	if opt.TsaCertificate.Issuer.String() != tsaCert.Issuer.String() {
		errMessage += "TSR cert issuer does not match provided TSA cert issuer"
	}

	if opt.TsaCertificate.SerialNumber.Cmp(tsaCert.SerialNumber) != 0 {
		if errMessage != "" {
			errMessage += ", TSR cert issuer does not match provided TSA cert issuer"
		} else {
			errMessage = "TSR cert issuer does not match provided TSA cert issuer"
		}
	}

	if errMessage != "" {
		return errors.New(errMessage)
	}
	return nil
}

// Verify the leaf certificate's subject and/or subject alternative name matches a provided subject
func VerifyLeafCertSubject(subject string, opts VerifyOpts) error {
	leafCertSubject := opts.TsaCertificate.Subject.String()
	if leafCertSubject != subject {
		return fmt.Errorf("Leaf cert subject %s does not match provided subject %s", leafCertSubject, subject)
	}
	return nil
}

func verifyExtendedKeyUsage(cert *x509.Certificate) error {
	certEKULen := len(cert.ExtKeyUsage)
	if certEKULen != 1 {
		return fmt.Errorf("cert has %d extended key usages, expected only one", certEKULen)
	}

	if cert.ExtKeyUsage[0] != x509.ExtKeyUsageTimeStamping {
		return fmt.Errorf("leaf cert EKU is not set to TimeStamping as required")
	}
	return nil
}

// Verify the TSA certificate and the intermediates (called "EKU chaining") all
// have the extended key usage set to only time stamping usage
func VerifyExtendedKeyUsageForLeafAndIntermediates(opts VerifyOpts) error {
	leafCert := opts.TsaCertificate
	err := verifyExtendedKeyUsage(leafCert)
	if err != nil {
		return fmt.Errorf("failed to verify EKU on leaf cert: %w", err)
	}

	for _, cert := range opts.Intermediates {
		err := verifyExtendedKeyUsage(cert)
		if err != nil {
			return fmt.Errorf("failed to verify EKU on intermediate cert: %w", err)
		}
	}
	return nil
}

// If embedded in the TSR, verify the TSR's leaf certificate matches a provided TSA certificate
func VerifyEmbeddedLeafCert(tsaCert *x509.Certificate, opts VerifyOpts) error {
	if opts.TsaCertificate != nil && !opts.TsaCertificate.Equal(tsaCert) {
		return fmt.Errorf("certificate embedded in the TSR does not match the provided TSA certificate")
	}
	return nil
}

// Verify the OID of the TSR matches an expected OID
func VerifyOID(oid []int, opts VerifyOpts) error {
	responseOid := opts.Oid
	if len(oid) != len(responseOid) {
		return fmt.Errorf("OID lengths do not match")
	}
	for i, v := range oid {
		if v != responseOid[i] {
			return fmt.Errorf("OID content does not match")
		}
	}
	return nil
}

// Verify the nonce - Mostly important for when the response is first returned
func VerifyNonce(requestNonce *big.Int, opts VerifyOpts) error {
	if opts.Nonce.Cmp(requestNonce) != 0 {
		return fmt.Errorf("incoming nonce %d does not match TSR nonce %d", requestNonce, opts.Nonce)
	}
	return nil
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

func CreateTimestampResponse(tsrBytes []byte) (timestamp.Timestamp, error) {
	// Verify the status of the TSR does not contain an error
	// when timestamp.ParseResponse tries to parse a TSR into a Timestamp
	// struct, it will verify and exit with an error if the TSR has an error status
	ts, err := timestamp.ParseResponse(tsrBytes)
	if err != nil {
		pe := timestamp.ParseError("")
		if errors.As(err, &pe) {
			return timestamp.Timestamp{}, fmt.Errorf("timestamp response is not valid: %w", err)
		}
		return timestamp.Timestamp{}, fmt.Errorf("error parsing response into Timestamp: %w", err)
	}
	return *ts, nil
}
