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
	"encoding/pem"
	"math/big"
	"encoding/asn1"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
)

type VerificationOpts struct {
	Oid asn1.ObjectIdentifier
	TsaCertificate *x509.Certificate
	Intermediates *x509.CertPool
	Roots *x509.CertPool
	Nonce *big.Int
	Subject string
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
	
	intermediatesPemCerts := []byte{}
	rootsPemCerts := []byte{}
	for len(pemCerts) > 0 {
		block, rest := pem.Decode(pemCerts)
		// if there is nothing left, we have found the last block
		// which should be the root
		if rest == nil {
			rootsPemCerts = append(rootsPemCerts, pem.EncodeToMemory(block)...)
		} else {
			intermediatesPemCerts = append(intermediatesPemCerts, pem.EncodeToMemory(block)...)
		}
		pemCerts = rest
	}

	intermediates := x509.NewCertPool()
	if ok := intermediates.AppendCertsFromPEM(intermediatesPemCerts); !ok {
		return VerificationOpts{}, fmt.Errorf("error parsing response into Timestamp while appending certs from PEM")
	}

	roots := x509.NewCertPool()
	if ok := roots.AppendCertsFromPEM(rootsPemCerts); !ok {
		return VerificationOpts{}, fmt.Errorf("error parsing response into Timestamp while appending certs from PEM")
	}

	opts := VerificationOpts{}
	opts.Oid = ts.Policy
	opts.TsaCertificate = ts.Certificates[0]
	opts.Intermediates = intermediates
	opts.Roots = roots
	opts.Nonce = ts.Nonce
	opts.Subject = ts.Certificates[0].Subject.String()

	return opts, nil
}

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

func VerifyNonce(requestNonce *big.Int, opts VerificationOpts) bool {
	return opts.Nonce.Cmp(requestNonce) == 0
}

// VerifyTimestampResponse the timestamp response using a timestamp certificate chain.
func VerifyTimestampResponse(tsrBytes []byte, artifact io.Reader, certPool *x509.CertPool) error {
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
