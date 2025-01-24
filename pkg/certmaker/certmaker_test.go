// Copyright 2024 The Sigstore Authors.
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
//

package certmaker

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	originalInitKMS = InitKMS
	testKey         *ecdsa.PrivateKey
)

// mockSignerVerifier implements signature.SignerVerifier and CryptoSignerVerifier for testing
type mockSignerVerifier struct {
	key              crypto.Signer
	err              error
	publicKeyFunc    func() (crypto.PublicKey, error)
	signMessageFunc  func(message io.Reader, opts ...signature.SignOption) ([]byte, error)
	cryptoSignerFunc func(ctx context.Context, errHandler func(error)) (crypto.Signer, crypto.SignerOpts, error)
}

func (m *mockSignerVerifier) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	if m.signMessageFunc != nil {
		return m.signMessageFunc(message, opts...)
	}
	if m.err != nil {
		return nil, m.err
	}
	digest := make([]byte, 32)
	if _, err := message.Read(digest); err != nil {
		return nil, err
	}
	return m.key.Sign(rand.Reader, digest, crypto.SHA256)
}

func (m *mockSignerVerifier) VerifySignature(_, _ io.Reader, _ ...signature.VerifyOption) error {
	return nil
}

func (m *mockSignerVerifier) PublicKey(_ ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	if m.publicKeyFunc != nil {
		return m.publicKeyFunc()
	}
	if m.err != nil {
		return nil, m.err
	}
	return m.key.Public(), nil
}

func (m *mockSignerVerifier) Close() error { return nil }

func (m *mockSignerVerifier) DefaultHashFunction() crypto.Hash { return crypto.SHA256 }

func (m *mockSignerVerifier) Bytes() ([]byte, error) { return nil, nil }

func (m *mockSignerVerifier) KeyID() (string, error) { return "", nil }

func (m *mockSignerVerifier) Status() error { return nil }

func (m *mockSignerVerifier) CryptoSigner(_ context.Context, _ func(error)) (crypto.Signer, crypto.SignerOpts, error) {
	if m.cryptoSignerFunc != nil {
		return m.cryptoSignerFunc(context.Background(), nil)
	}
	if m.err != nil {
		return nil, nil, m.err
	}
	return m.key, crypto.SHA256, nil
}

func init() {
	var err error
	testKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("failed to generate test key: %v", err))
	}

	InitKMS = func(_ context.Context, config KMSConfig) (signature.SignerVerifier, error) {
		if config.Options != nil && config.Options["mock-leaf-error"] == "true" {
			return nil, fmt.Errorf("leaf signing error")
		}
		return &mockSignerVerifier{
			key: testKey,
		}, nil
	}
}

func TestMain(m *testing.M) {
	code := m.Run()

	InitKMS = originalInitKMS

	os.Exit(code)
}

func TestValidateKMSConfig(t *testing.T) {
	tests := []struct {
		name      string
		config    KMSConfig
		wantError string
	}{
		{
			name: "empty_KMS_type",
			config: KMSConfig{
				RootKeyID: "key1",
				LeafKeyID: "key2",
			},
			wantError: "KMS type cannot be empty",
		},
		{
			name: "missing_key_IDs",
			config: KMSConfig{
				Type: "awskms",
				Options: map[string]string{
					"aws-region": "us-west-2",
				},
			},
			wantError: "RootKeyID must be specified",
		},
		{
			name: "AWS_KMS_missing_region",
			config: KMSConfig{
				Type:      "awskms",
				RootKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
				LeafKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
			},
			wantError: "options map is required for AWS KMS",
		},
		{
			name: "AWS_KMS_invalid_key_format",
			config: KMSConfig{
				Type:      "awskms",
				RootKeyID: "invalid-key-id",
				LeafKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
				Options:   map[string]string{"aws-region": "us-west-2"},
			},
			wantError: "awskms RootKeyID must start with 'arn:aws:kms:' or 'alias/'",
		},
		{
			name: "valid_AWS_KMS_config",
			config: KMSConfig{
				Type:      "awskms",
				RootKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
				LeafKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
				Options:   map[string]string{"aws-region": "us-west-2"},
			},
		},
		{
			name: "Azure_KMS_missing_tenant_id",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "azurekms:name=key1;vault=vault1",
				LeafKeyID: "azurekms:name=key2;vault=vault1",
			},
			wantError: "options map is required for Azure KMS",
		},
		{
			name: "Azure_KMS_invalid_key_format",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "invalid-key-id",
				LeafKeyID: "azurekms:name=key2;vault=vault1",
				Options:   map[string]string{"azure-tenant-id": "tenant-id"},
			},
			wantError: "azurekms RootKeyID must start with 'azurekms:name='",
		},
		{
			name: "valid_Azure_KMS_config",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "azurekms:name=key1;vault=vault1",
				LeafKeyID: "azurekms:name=key2;vault=vault1",
				Options:   map[string]string{"azure-tenant-id": "tenant-id"},
			},
		},
		{
			name: "GCP_KMS_invalid_key_format",
			config: KMSConfig{
				Type:      "gcpkms",
				RootKeyID: "invalid/key/path",
				LeafKeyID: "projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/my-key/cryptoKeyVersions/1",
				Options:   map[string]string{"gcp-credentials-file": "/path/to/creds.json"},
			},
			wantError: "gcpkms RootKeyID must start with 'projects/'",
		},
		{
			name: "valid_GCP_KMS_config",
			config: KMSConfig{
				Type:      "gcpkms",
				RootKeyID: "projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/my-key/cryptoKeyVersions/1",
				LeafKeyID: "projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/my-key/cryptoKeyVersions/1",
				Options:   map[string]string{"gcp-credentials-file": "/path/to/creds.json"},
			},
		},
		{
			name: "HashiVault_KMS_missing_token",
			config: KMSConfig{
				Type:      "hashivault",
				RootKeyID: "transit/keys/root-key",
				LeafKeyID: "transit/keys/leaf-key",
				Options:   map[string]string{"vault-address": "http://localhost:8200"},
			},
			wantError: "vault-token is required for HashiVault KMS",
		},
		{
			name: "HashiVault_KMS_missing_address",
			config: KMSConfig{
				Type:      "hashivault",
				RootKeyID: "transit/keys/root-key",
				LeafKeyID: "transit/keys/leaf-key",
				Options:   map[string]string{"vault-token": "token"},
			},
			wantError: "vault-address is required for HashiVault KMS",
		},
		{
			name: "valid_HashiVault_KMS_config",
			config: KMSConfig{
				Type:      "hashivault",
				RootKeyID: "transit/keys/root-key",
				LeafKeyID: "transit/keys/leaf-key",
				Options: map[string]string{
					"vault-token":   "token",
					"vault-address": "http://localhost:8200",
				},
			},
		},
		{
			name: "aws_kms_alias",
			config: KMSConfig{
				Type:      "awskms",
				RootKeyID: "alias/my-key",
				LeafKeyID: "alias/my-leaf-key",
				Options:   map[string]string{"aws-region": "us-west-2"},
			},
		},
		{
			name: "aws_kms_empty_alias",
			config: KMSConfig{
				Type:      "awskms",
				RootKeyID: "alias/",
				LeafKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
				Options:   map[string]string{"aws-region": "us-west-2"},
			},
			wantError: "alias name cannot be empty",
		},
		{
			name: "gcp_kms_missing_components",
			config: KMSConfig{
				Type:      "gcpkms",
				RootKeyID: "projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/my-key",
				LeafKeyID: "projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/my-key/cryptoKeyVersions/1",
				Options:   map[string]string{"gcp-credentials-file": "/path/to/creds.json"},
			},
			wantError: "must contain '/cryptoKeyVersions/'",
		},
		{
			name: "azure_kms_missing_vault",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "azurekms:name=key1",
				LeafKeyID: "azurekms:name=key2;vault=vault1",
				Options:   map[string]string{"azure-tenant-id": "tenant-id"},
			},
			wantError: "must contain ';vault=' parameter",
		},
		{
			name: "azure_kms_empty_vault",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "azurekms:name=key1;vault=",
				LeafKeyID: "azurekms:name=key2;vault=vault1",
				Options:   map[string]string{"azure-tenant-id": "tenant-id"},
			},
			wantError: "vault name cannot be empty",
		},
		{
			name: "hashivault_kms_invalid_path",
			config: KMSConfig{
				Type:      "hashivault",
				RootKeyID: "invalid/path",
				LeafKeyID: "transit/keys/leaf-key",
				Options: map[string]string{
					"vault-token":   "token",
					"vault-address": "http://localhost:8200",
				},
			},
			wantError: "hashivault RootKeyID must be in format: transit/keys/keyname",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKMSConfig(tt.config)
			if tt.wantError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCreateCertificates(t *testing.T) {
	// Create temporary directory for test files
	tmpDir := t.TempDir()

	// Create test files
	rootTmplPath := filepath.Join(tmpDir, "root-template.json")
	leafTmplPath := filepath.Join(tmpDir, "leaf-template.json")
	intermediateTmplPath := filepath.Join(tmpDir, "intermediate-template.json")
	invalidTmplPath := filepath.Join(tmpDir, "invalid-template.json")
	rootCertPath := filepath.Join(tmpDir, "root.crt")
	intermediateCertPath := filepath.Join(tmpDir, "intermediate.crt")
	leafCertPath := filepath.Join(tmpDir, "leaf.crt")

	// Write test templates
	err := os.WriteFile(rootTmplPath, []byte(`{
		"subject": {
			"commonName": "Test Root CA",
			"organization": ["Test Org"],
			"country": ["US"]
		},
		"keyUsages": ["certSign", "crlSign"]
	}`), 0600)
	require.NoError(t, err)

	err = os.WriteFile(leafTmplPath, []byte(`{
		"subject": {
			"commonName": "Test Leaf CA",
			"organization": ["Test Org"],
			"country": ["US"]
		},
		"keyUsages": ["digitalSignature", "timestamping"]
	}`), 0600)
	require.NoError(t, err)

	err = os.WriteFile(intermediateTmplPath, []byte(`{
		"subject": {
			"commonName": "Test Intermediate CA",
			"organization": ["Test Org"],
			"country": ["US"]
		},
		"keyUsages": ["certSign", "crlSign"]
	}`), 0600)
	require.NoError(t, err)

	err = os.WriteFile(invalidTmplPath, []byte("{ invalid json"), 0600)
	require.NoError(t, err)

	tests := []struct {
		name                 string
		config               KMSConfig
		rootTmplPath         string
		leafTmplPath         string
		rootCertPath         string
		leafCertPath         string
		intermediateKeyID    string
		intermediateTmplPath string
		intermediateCertPath string
		rootLifetime         time.Duration
		intermediateLifetime time.Duration
		leafLifetime         time.Duration
		mockSetup            func() (signature.SignerVerifier, error)
		wantError            string
	}{
		{
			name: "invalid_root_template",
			config: KMSConfig{
				Type:      "awskms",
				RootKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
				LeafKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
				Options:   map[string]string{"aws-region": "us-west-2"},
			},
			rootTmplPath:         invalidTmplPath,
			leafTmplPath:         leafTmplPath,
			rootCertPath:         rootCertPath,
			leafCertPath:         leafCertPath,
			rootLifetime:         87600 * time.Hour,
			intermediateLifetime: 43800 * time.Hour,
			leafLifetime:         8760 * time.Hour,
			mockSetup: func() (signature.SignerVerifier, error) {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return &mockSignerVerifier{key: key}, nil
			},
			wantError: "error parsing template",
		},
		{
			name: "invalid_leaf_template",
			config: KMSConfig{
				Type:      "awskms",
				RootKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
				LeafKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
				Options:   map[string]string{"aws-region": "us-west-2"},
			},
			rootTmplPath:         rootTmplPath,
			leafTmplPath:         invalidTmplPath,
			rootCertPath:         rootCertPath,
			leafCertPath:         leafCertPath,
			rootLifetime:         87600 * time.Hour,
			intermediateLifetime: 43800 * time.Hour,
			leafLifetime:         8760 * time.Hour,
			mockSetup: func() (signature.SignerVerifier, error) {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return &mockSignerVerifier{key: key}, nil
			},
			wantError: "error parsing template",
		},
		{
			name: "invalid_intermediate_template",
			config: KMSConfig{
				Type:      "awskms",
				RootKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
				LeafKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
				Options:   map[string]string{"aws-region": "us-west-2"},
			},
			rootTmplPath:         rootTmplPath,
			leafTmplPath:         leafTmplPath,
			rootCertPath:         rootCertPath,
			leafCertPath:         leafCertPath,
			intermediateKeyID:    "intermediate-key",
			intermediateTmplPath: invalidTmplPath,
			intermediateCertPath: intermediateCertPath,
			rootLifetime:         87600 * time.Hour,
			intermediateLifetime: 43800 * time.Hour,
			leafLifetime:         8760 * time.Hour,
			mockSetup: func() (signature.SignerVerifier, error) {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return &mockSignerVerifier{key: key}, nil
			},
			wantError: "error parsing template",
		},
		{
			name: "root_only_chain",
			config: KMSConfig{
				Type:      "awskms",
				RootKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
				LeafKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
				Options:   map[string]string{"aws-region": "us-west-2"},
			},
			rootTmplPath:         rootTmplPath,
			leafTmplPath:         leafTmplPath,
			rootCertPath:         rootCertPath,
			leafCertPath:         leafCertPath,
			rootLifetime:         87600 * time.Hour,
			intermediateLifetime: 43800 * time.Hour,
			leafLifetime:         8760 * time.Hour,
			mockSetup: func() (signature.SignerVerifier, error) {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return &mockSignerVerifier{key: key}, nil
			},
		},
		{
			name: "full_chain",
			config: KMSConfig{
				Type:      "awskms",
				RootKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
				LeafKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
				Options:   map[string]string{"aws-region": "us-west-2"},
			},
			rootTmplPath:         rootTmplPath,
			leafTmplPath:         leafTmplPath,
			rootCertPath:         rootCertPath,
			leafCertPath:         leafCertPath,
			intermediateKeyID:    "intermediate-key",
			intermediateTmplPath: intermediateTmplPath,
			intermediateCertPath: intermediateCertPath,
			rootLifetime:         87600 * time.Hour,
			intermediateLifetime: 43800 * time.Hour,
			leafLifetime:         8760 * time.Hour,
			mockSetup: func() (signature.SignerVerifier, error) {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return &mockSignerVerifier{key: key}, nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sv signature.SignerVerifier
			var err error
			if tt.mockSetup != nil {
				sv, err = tt.mockSetup()
				require.NoError(t, err)
				InitKMS = func(_ context.Context, _ KMSConfig) (signature.SignerVerifier, error) {
					return sv, nil
				}
			}

			err = CreateCertificates(sv, tt.config,
				tt.rootTmplPath,
				tt.leafTmplPath,
				tt.rootCertPath,
				tt.leafCertPath,
				tt.intermediateKeyID,
				tt.intermediateTmplPath,
				tt.intermediateCertPath,
				tt.rootLifetime,
				tt.intermediateLifetime,
				tt.leafLifetime)

			if tt.wantError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			} else {
				require.NoError(t, err)
				// Verify files were created
				_, err = os.Stat(tt.rootCertPath)
				require.NoError(t, err)
				_, err = os.Stat(tt.leafCertPath)
				require.NoError(t, err)
				if tt.intermediateKeyID != "" {
					_, err = os.Stat(tt.intermediateCertPath)
					require.NoError(t, err)
				}
			}
		})
	}
}

func TestCreateCertificatesWithWriteErrors(t *testing.T) {
	defer func() { InitKMS = originalInitKMS }()

	InitKMS = func(_ context.Context, _ KMSConfig) (signature.SignerVerifier, error) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return &mockSignerVerifier{
			key: key,
		}, nil
	}

	tmpDir := t.TempDir()
	readOnlyDir := filepath.Join(tmpDir, "readonly")
	err := os.MkdirAll(readOnlyDir, 0755)
	require.NoError(t, err)
	err = os.Chmod(readOnlyDir, 0500)
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockSigner := &mockSignerVerifier{
		key: key,
	}

	config := KMSConfig{
		Type:      "mock",
		RootKeyID: "test-root-key",
		LeafKeyID: "test-leaf-key",
	}

	t.Run("write_error", func(t *testing.T) {
		rootCertPath := filepath.Join(readOnlyDir, "root.crt")
		leafCertPath := filepath.Join(readOnlyDir, "leaf.crt")

		err := CreateCertificates(mockSigner, config, "", "", rootCertPath, leafCertPath, "", "", "",
			87600*time.Hour, 43800*time.Hour, 8760*time.Hour)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "error writing root certificate")
	})
}

// CertMaker handles the creation of certificates using templates and KMS
type CertMaker struct {
	RootTemplatePath     string
	IntermediateTemplate string
	LeafTemplatePath     string
	KMSConfig            KMSConfig
}

// CreateCertificates creates root, intermediate, and leaf certificates using the configured templates and KMS
func (c *CertMaker) CreateCertificates(_ context.Context) error {
	// Mock implementation for testing
	switch {
	case c.KMSConfig.RootKeyID == "error-root":
		return fmt.Errorf("error creating root certificate")
	case c.KMSConfig.IntermediateKeyID == "error-intermediate":
		return fmt.Errorf("error creating intermediate certificate")
	case c.KMSConfig.LeafKeyID == "error-leaf":
		return fmt.Errorf("error creating leaf certificate")
	case c.RootTemplatePath != "" && !fileExists(c.RootTemplatePath):
		return fmt.Errorf("error reading root template")
	case c.IntermediateTemplate != "" && !fileExists(c.IntermediateTemplate):
		return fmt.Errorf("error reading intermediate template")
	case c.LeafTemplatePath != "" && !fileExists(c.LeafTemplatePath):
		return fmt.Errorf("error reading leaf template")
	}
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
