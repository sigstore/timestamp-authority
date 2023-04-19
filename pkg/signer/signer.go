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
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"

	// Register the provider-specific plugins
	_ "github.com/sigstore/sigstore/pkg/signature/kms/aws"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/azure"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/gcp"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/hashivault"
)

const KMSScheme = "kms"
const TinkScheme = "tink"
const MemoryScheme = "memory"
const FileScheme = "file"

func getHashFuncEllipticCurve(hashFuncStr string) (crypto.Hash, elliptic.Curve, error) {
	switch hashFuncStr {
	case "sha256":
		return crypto.SHA256, elliptic.P256(), nil
	case "sha384":
		return crypto.SHA384, elliptic.P384(), nil
	case "sha512":
		return crypto.SHA512, elliptic.P521(), nil
	default:
		return 0, nil, fmt.Errorf("invalid hash algorithm - must be either sha256, sha384, or sha512")
	}
}

func NewCryptoSigner(ctx context.Context, signer, kmsKey, tinkKmsKey, tinkKeysetPath, hcVaultToken, fileSignerPath, fileSignerPasswd, signerHashFunc string) (crypto.Signer, error) {
	switch signer {
	case MemoryScheme:
		hashFunc, curve, err := getHashFuncEllipticCurve(signerHashFunc)
		if err != nil {
			return nil, err
		}
		sv, _, err := signature.NewECDSASignerVerifier(curve, rand.Reader, hashFunc)
		return sv, err
	case FileScheme:
		hashFunc, _, err := getHashFuncEllipticCurve(signerHashFunc)
		if err != nil {
			return nil, err
		}
		return NewFileSigner(fileSignerPath, fileSignerPasswd, hashFunc)
	case KMSScheme:
		hashFunc, _, err := getHashFuncEllipticCurve(signerHashFunc)
		if err != nil {
			return nil, err
		}
		signer, err := kms.Get(ctx, kmsKey, hashFunc)
		if err != nil {
			return nil, err
		}
		s, _, err := signer.CryptoSigner(ctx, func(err error) {})
		return s, err
	case TinkScheme:
		primaryKey, err := GetPrimaryKey(ctx, tinkKmsKey, hcVaultToken)
		if err != nil {
			return nil, err
		}
		hashFunc, _, err := getHashFuncEllipticCurve(signerHashFunc)
		if err != nil {
			return nil, err
		}
		return NewTinkSigner(ctx, tinkKeysetPath, primaryKey, hashFunc)
	default:
		return nil, fmt.Errorf("unsupported signer type: %s", signer)
	}
}
