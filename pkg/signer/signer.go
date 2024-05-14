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
	"strings"

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

func NewCryptoSigner(ctx context.Context, hash crypto.Hash, signer, kmsKey, tinkKmsKey, tinkKeysetPath, hcVaultToken, fileSignerPath, fileSignerPasswd string) (crypto.Signer, error) {
	switch signer {
	case MemoryScheme:
		sv, _, err := signature.NewECDSASignerVerifier(elliptic.P256(), rand.Reader, crypto.SHA256)
		return sv, err
	case FileScheme:
		return NewFileSigner(fileSignerPath, fileSignerPasswd, hash)
	case KMSScheme:
		signer, err := kms.Get(ctx, kmsKey, hash) // hash is ignored for all KMS providers except Hashivault
		if err != nil {
			return nil, err
		}
		s, _, err := signer.CryptoSigner(ctx, func(_ error) {})
		return s, err
	case TinkScheme:
		primaryKey, err := GetPrimaryKey(ctx, tinkKmsKey, hcVaultToken)
		if err != nil {
			return nil, err
		}
		return NewTinkSigner(ctx, tinkKeysetPath, primaryKey)
	default:
		return nil, fmt.Errorf("unsupported signer type: %s", signer)
	}
}

func HashToAlg(signerHashAlg string) (crypto.Hash, error) {
	lowercaseAlg := strings.ToLower(signerHashAlg)
	var hash crypto.Hash
	switch lowercaseAlg {
	case "sha256":
		hash = crypto.SHA256
	case "sha384":
		hash = crypto.SHA384
	case "sha512":
		hash = crypto.SHA512
	default:
		return crypto.Hash(0), fmt.Errorf("unsupported hash algorithm: %s", lowercaseAlg)
	}
	return hash, nil
}
