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
	"errors"
	"os"
	"path/filepath"
	"strings"

	tinkUtils "github.com/sigstore/sigstore/pkg/signature/tink"
	"github.com/tink-crypto/tink-go-awskms/v2/integration/awskms"
	"github.com/tink-crypto/tink-go-gcpkms/v2/integration/gcpkms"
	"github.com/tink-crypto/tink-go-hcvault/v2/integration/hcvault"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// NewTinkSigner creates a signer by decrypting a local Tink keyset with a remote KMS encryption key
func NewTinkSigner(tinkKeysetPath string, primaryKey tink.AEAD) (crypto.Signer, error) {
	f, err := os.Open(filepath.Clean(tinkKeysetPath))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	kh, err := keyset.Read(keyset.NewJSONReader(f), primaryKey)
	if err != nil {
		return nil, err
	}
	signer, err := tinkUtils.KeyHandleToSigner(kh)
	if err != nil {
		return nil, err
	}
	return signer, nil
}

// GetPrimaryKey returns a Tink AEAD encryption key from KMS
// Supports GCP, AWS, and Vault
func GetPrimaryKey(ctx context.Context, kmsKey, hcVaultToken string) (tink.AEAD, error) {
	switch {
	case strings.HasPrefix(kmsKey, "gcp-kms://"):
		gcpClient, err := gcpkms.NewClientWithOptions(ctx, kmsKey)
		if err != nil {
			return nil, err
		}
		registry.RegisterKMSClient(gcpClient)
		return gcpClient.GetAEAD(kmsKey)
	case strings.HasPrefix(kmsKey, "aws-kms://"):
		awsClient, err := awskms.NewClientWithOptions(kmsKey)
		if err != nil {
			return nil, err
		}
		registry.RegisterKMSClient(awsClient)
		return awsClient.GetAEAD(kmsKey)
	case strings.HasPrefix(kmsKey, "hcvault://"):
		hcVaultClient, err := hcvault.NewClient(kmsKey, nil, hcVaultToken)
		if err != nil {
			return nil, err
		}
		registry.RegisterKMSClient(hcVaultClient)
		return hcVaultClient.GetAEAD(kmsKey)
	default:
		return nil, errors.New("unsupported Tink KMS key type")
	}
}
