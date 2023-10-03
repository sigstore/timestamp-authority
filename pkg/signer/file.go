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
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"

	"github.com/sigstore/sigstore/pkg/signature"
	"go.step.sm/crypto/pemutil"
)

// File returns a file-based signer and verifier, used for local testing
type File struct {
	crypto.Signer
}

func NewFileSigner(keyPath, keyPass string, hash crypto.Hash) (*File, error) {
	opaqueKey, err := pemutil.Read(keyPath, pemutil.WithPassword([]byte(keyPass)))
	if err != nil {
		return nil, fmt.Errorf("file: provide a valid signer, %s is not valid: %w", keyPath, err)
	}
	// Cannot use signature.LoadSignerVerifier because the SignerVerifier interface does not extend crypto.Signer
	switch pk := opaqueKey.(type) {
	case *rsa.PrivateKey:
		signer, err := signature.LoadRSAPKCS1v15SignerVerifier(pk, hash)
		if err != nil {
			return nil, err
		}
		return &File{signer}, nil
	case *ecdsa.PrivateKey:
		signer, err := signature.LoadECDSASignerVerifier(pk, hash)
		if err != nil {
			return nil, err
		}
		return &File{signer}, nil
	case ed25519.PrivateKey:
		signer, err := signature.LoadED25519SignerVerifier(pk)
		if err != nil {
			return nil, err
		}
		return &File{signer}, nil
	default:
		return nil, fmt.Errorf("unsupported private key type, must be RSA, ECDSA, or ED25519")
	}
}
