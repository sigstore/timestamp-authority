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
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSignerVerifier implements signature.SignerVerifier for testing
type mockSignerVerifier struct {
	key             crypto.PrivateKey
	err             error
	publicKeyFunc   func() (crypto.PublicKey, error)
	signMessageFunc func(message io.Reader) ([]byte, error)
}

func (m *mockSignerVerifier) PublicKey(_ ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	if m.publicKeyFunc != nil {
		return m.publicKeyFunc()
	}
	if m.err != nil {
		return nil, m.err
	}
	if m.key != nil {
		switch k := m.key.(type) {
		case *ecdsa.PrivateKey:
			return k.Public(), nil
		default:
			return nil, fmt.Errorf("unsupported key type")
		}
	}
	return nil, fmt.Errorf("no key or public key function set")
}

func (m *mockSignerVerifier) SignMessage(message io.Reader, _ ...signature.SignOption) ([]byte, error) {
	if m.signMessageFunc != nil {
		return m.signMessageFunc(message)
	}
	if m.err != nil {
		return nil, m.err
	}
	if m.key == nil {
		return nil, fmt.Errorf("no key set")
	}

	// Read the message
	msgBytes, err := io.ReadAll(message)
	if err != nil {
		return nil, fmt.Errorf("error reading message: %w", err)
	}

	// Hash the message with SHA256
	h := crypto.SHA256.New()
	h.Write(msgBytes)
	digest := h.Sum(nil)

	// Use the private key to sign
	switch k := m.key.(type) {
	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(rand.Reader, k, digest)
	default:
		return nil, fmt.Errorf("unsupported key type")
	}
}

func (m *mockSignerVerifier) VerifySignature(_, _ io.Reader, _ ...signature.VerifyOption) error {
	return nil
}

func (m *mockSignerVerifier) Close() error {
	return nil
}

func (m *mockSignerVerifier) DefaultHashFunction() crypto.Hash {
	return crypto.SHA256
}

func (m *mockSignerVerifier) Bytes() ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockSignerVerifier) KeyID() (string, error) {
	return "mock-key-id", nil
}

func (m *mockSignerVerifier) Status() error {
	return nil
}

// CryptoSigner implements the CryptoSignerVerifier interface
func (m *mockSignerVerifier) CryptoSigner(_ context.Context, _ func(error)) (crypto.Signer, crypto.SignerOpts, error) {
	if m.err != nil {
		return nil, nil, m.err
	}
	if m.key == nil {
		return nil, nil, fmt.Errorf("no key set")
	}
	switch k := m.key.(type) {
	case *ecdsa.PrivateKey:
		return k, crypto.SHA256, nil
	default:
		return nil, nil, fmt.Errorf("unsupported key type")
	}
}

// At package level
var (
	// Store the original function
	originalInitKMS = InitKMS // Changed from initKMS to InitKMS
)

func TestValidateKMSConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  KMSConfig
		wantErr string
	}{
		{
			name:    "empty_KMS_type",
			config:  KMSConfig{},
			wantErr: "KMS type cannot be empty",
		},
		{
			name:    "missing_key_IDs",
			config:  KMSConfig{Type: "awskms"},
			wantErr: "RootKeyID must be specified",
		},
		{
			name: "AWS_KMS_missing_region",
			config: KMSConfig{
				Type:              "awskms",
				RootKeyID:         "alias/test-root-key",
				IntermediateKeyID: "alias/test-intermediate-key",
				LeafKeyID:         "alias/test-leaf-key",
				Options:           map[string]string{},
			},
			wantErr: "aws-region is required for AWS KMS",
		},
		{
			name: "valid_AWS_KMS_config",
			config: KMSConfig{
				Type:              "awskms",
				RootKeyID:         "alias/test-root-key",
				IntermediateKeyID: "alias/test-intermediate-key",
				LeafKeyID:         "alias/test-leaf-key",
				Options:           map[string]string{"aws-region": "us-west-2"},
			},
		},
		{
			name: "valid_Azure_KMS_config",
			config: KMSConfig{
				Type:              "azurekms",
				RootKeyID:         "azurekms:name=test-root-key;vault=test-vault",
				IntermediateKeyID: "azurekms:name=test-intermediate-key;vault=test-vault",
				LeafKeyID:         "azurekms:name=test-leaf-key;vault=test-vault",
				Options:           map[string]string{"azure-tenant-id": "test-tenant"},
			},
		},
		{
			name: "valid_GCP_KMS_config",
			config: KMSConfig{
				Type:              "gcpkms",
				RootKeyID:         "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1",
				IntermediateKeyID: "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/test-intermediate-key/cryptoKeyVersions/1",
				LeafKeyID:         "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/test-leaf-key/cryptoKeyVersions/1",
			},
		},
		{
			name: "valid_HashiVault_KMS_config",
			config: KMSConfig{
				Type:              "hashivault",
				RootKeyID:         "test-key",
				IntermediateKeyID: "test-intermediate-key",
				LeafKeyID:         "test-leaf-key",
				Options:           map[string]string{"vault-token": "test-token", "vault-address": "http://localhost:8200"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKMSConfig(tt.config)
			if tt.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateTemplatePath(t *testing.T) {
	tests := []struct {
		name      string
		setup     func() string
		wantError string
	}{
		{
			name: "nonexistent_file",
			setup: func() string {
				return "/nonexistent/template.json"
			},
			wantError: "no such file or directory",
		},
		{
			name: "wrong_extension",
			setup: func() string {
				tmpFile, err := os.CreateTemp("", "template-*.txt")
				require.NoError(t, err)
				defer tmpFile.Close()
				return tmpFile.Name()
			},
			wantError: "template file must have .json extension",
		},
		{
			name: "valid_JSON_template",
			setup: func() string {
				tmpFile, err := os.CreateTemp("", "template-*.json")
				require.NoError(t, err)
				defer tmpFile.Close()
				return tmpFile.Name()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setup()
			defer func() {
				if _, err := os.Stat(path); err == nil {
					os.Remove(path)
				}
			}()

			err := ValidateTemplatePath(path)
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
	// Save original and restore after test
	defer func() { InitKMS = originalInitKMS }() // Changed from initKMS to InitKMS

	// Create a mock key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockSV := &mockSignerVerifier{
		key: key,
		publicKeyFunc: func() (crypto.PublicKey, error) {
			return key.Public(), nil
		},
		signMessageFunc: func(message io.Reader) ([]byte, error) {
			msgBytes, err := io.ReadAll(message)
			if err != nil {
				return nil, err
			}
			h := crypto.SHA256.New()
			h.Write(msgBytes)
			digest := h.Sum(nil)
			return ecdsa.SignASN1(rand.Reader, key, digest)
		},
	}

	// Replace initKMS with mock version
	InitKMS = func(_ context.Context, _ KMSConfig) (signature.SignerVerifier, error) {
		return mockSV, nil
	}

	tests := []struct {
		name      string
		setup     func(t *testing.T) (string, KMSConfig, signature.SignerVerifier)
		wantError string
	}{
		{
			name: "successful_certificate_creation",
			setup: func(t *testing.T) (string, KMSConfig, signature.SignerVerifier) {
				tmpDir, err := os.MkdirTemp("", "cert-test-*")
				require.NoError(t, err)

				outDir := filepath.Join(tmpDir, "out")
				require.NoError(t, os.MkdirAll(outDir, 0755))

				rootTemplate := filepath.Join(tmpDir, "root.json")
				err = os.WriteFile(rootTemplate, []byte(`{
					"subject": {"commonName": "Test Root CA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 1},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)

				leafTemplate := filepath.Join(tmpDir, "leaf.json")
				err = os.WriteFile(leafTemplate, []byte(`{
					"subject": {"commonName": "Test Leaf"},
					"keyUsage": ["digitalSignature"],
					"extKeyUsage": ["TimeStamping"],
					"basicConstraints": {"isCA": false},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)

				intermediateTemplate := filepath.Join(tmpDir, "intermediate.json")
				err = os.WriteFile(intermediateTemplate, []byte(`{
					"subject": {"commonName": "Test Intermediate CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 0},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)

				return tmpDir, KMSConfig{
					Type:              "awskms",
					RootKeyID:         "alias/root-key",
					IntermediateKeyID: "alias/intermediate-key",
					LeafKeyID:         "alias/leaf-key",
					Options:           map[string]string{"region": "us-west-2"},
				}, mockSV
			},
		},
		{
			name: "invalid_template_path",
			setup: func(t *testing.T) (string, KMSConfig, signature.SignerVerifier) {
				tmpDir, err := os.MkdirTemp("", "cert-test-*")
				require.NoError(t, err)

				outDir := filepath.Join(tmpDir, "out")
				require.NoError(t, os.MkdirAll(outDir, 0755))

				return tmpDir, KMSConfig{
					Type:      "awskms",
					RootKeyID: "alias/root-key",
					LeafKeyID: "alias/leaf-key",
				}, mockSV
			},
			wantError: "error parsing root template",
		},
		{
			name: "invalid_root_template_content",
			setup: func(t *testing.T) (string, KMSConfig, signature.SignerVerifier) {
				tmpDir, err := os.MkdirTemp("", "cert-test-*")
				require.NoError(t, err)

				rootTemplate := filepath.Join(tmpDir, "root.json")
				err = os.WriteFile(rootTemplate, []byte(`{invalid json`), 0600)
				require.NoError(t, err)

				outDir := filepath.Join(tmpDir, "out")
				require.NoError(t, os.MkdirAll(outDir, 0755))

				return tmpDir, KMSConfig{
					Type:      "awskms",
					RootKeyID: "alias/root-key",
					LeafKeyID: "alias/leaf-key",
				}, mockSV
			},
			wantError: "error parsing root template",
		},
		{
			name: "signer_error",
			setup: func(t *testing.T) (string, KMSConfig, signature.SignerVerifier) {
				tmpDir, err := os.MkdirTemp("", "cert-test-*")
				require.NoError(t, err)

				rootTemplate := filepath.Join(tmpDir, "root.json")
				err = os.WriteFile(rootTemplate, []byte(`{
					"subject": {"commonName": "Test Root CA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 1},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)

				outDir := filepath.Join(tmpDir, "out")
				require.NoError(t, os.MkdirAll(outDir, 0755))

				errorMockSV := &mockSignerVerifier{
					key: key,
					err: fmt.Errorf("signer error"),
				}

				return tmpDir, KMSConfig{
					Type:      "awskms",
					RootKeyID: "alias/root-key",
					LeafKeyID: "alias/leaf-key",
				}, errorMockSV
			},
			wantError: "error getting root public key",
		},
		{
			name: "invalid_intermediate_template",
			setup: func(t *testing.T) (string, KMSConfig, signature.SignerVerifier) {
				tmpDir, err := os.MkdirTemp("", "cert-test-*")
				require.NoError(t, err)

				rootTemplate := filepath.Join(tmpDir, "root.json")
				err = os.WriteFile(rootTemplate, []byte(`{
					"subject": {"commonName": "Test Root CA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 1},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)

				intermediateTemplate := filepath.Join(tmpDir, "intermediate.json")
				err = os.WriteFile(intermediateTemplate, []byte(`{invalid json`), 0600)
				require.NoError(t, err)

				outDir := filepath.Join(tmpDir, "out")
				require.NoError(t, os.MkdirAll(outDir, 0755))

				return tmpDir, KMSConfig{
					Type:              "awskms",
					RootKeyID:         "alias/root-key",
					IntermediateKeyID: "alias/intermediate-key",
					LeafKeyID:         "alias/leaf-key",
				}, mockSV
			},
			wantError: "error parsing intermediate template",
		},
		{
			name: "invalid_leaf_template",
			setup: func(t *testing.T) (string, KMSConfig, signature.SignerVerifier) {
				tmpDir, err := os.MkdirTemp("", "cert-test-*")
				require.NoError(t, err)

				rootTemplate := filepath.Join(tmpDir, "root.json")
				err = os.WriteFile(rootTemplate, []byte(`{
					"subject": {"commonName": "Test Root CA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 1},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)

				leafTemplate := filepath.Join(tmpDir, "leaf.json")
				err = os.WriteFile(leafTemplate, []byte(`{invalid json`), 0600)
				require.NoError(t, err)

				outDir := filepath.Join(tmpDir, "out")
				require.NoError(t, os.MkdirAll(outDir, 0755))

				return tmpDir, KMSConfig{
					Type:      "awskms",
					RootKeyID: "alias/root-key",
					LeafKeyID: "alias/leaf-key",
				}, mockSV
			},
			wantError: "error parsing leaf template",
		},
		{
			name: "root_cert_write_error",
			setup: func(t *testing.T) (string, KMSConfig, signature.SignerVerifier) {
				tmpDir, err := os.MkdirTemp("", "cert-test-*")
				require.NoError(t, err)

				rootTemplate := filepath.Join(tmpDir, "root.json")
				err = os.WriteFile(rootTemplate, []byte(`{
					"subject": {"commonName": "Test Root CA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 1},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)

				// Create a directory where a file should be to cause a write error
				rootCertDir := filepath.Join(tmpDir, "out", "root.crt")
				require.NoError(t, os.MkdirAll(rootCertDir, 0755))

				return tmpDir, KMSConfig{
					Type:      "awskms",
					RootKeyID: "alias/root-key",
					LeafKeyID: "alias/leaf-key",
				}, mockSV
			},
			wantError: "error writing root certificate",
		},
		{
			name: "successful_certificate_creation_without_intermediate",
			setup: func(t *testing.T) (string, KMSConfig, signature.SignerVerifier) {
				tmpDir, err := os.MkdirTemp("", "cert-test-*")
				require.NoError(t, err)

				outDir := filepath.Join(tmpDir, "out")
				require.NoError(t, os.MkdirAll(outDir, 0755))

				rootTemplate := filepath.Join(tmpDir, "root.json")
				err = os.WriteFile(rootTemplate, []byte(`{
					"subject": {"commonName": "Test Root CA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 1},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)

				leafTemplate := filepath.Join(tmpDir, "leaf.json")
				err = os.WriteFile(leafTemplate, []byte(`{
					"subject": {"commonName": "Test Leaf"},
					"keyUsage": ["digitalSignature"],
					"extKeyUsage": ["TimeStamping"],
					"basicConstraints": {"isCA": false},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)

				return tmpDir, KMSConfig{
					Type:      "awskms",
					RootKeyID: "alias/root-key",
					LeafKeyID: "alias/leaf-key",
					Options:   map[string]string{"region": "us-west-2"},
				}, mockSV
			},
		},
		{
			name: "successful_certificate_creation_with_intermediate",
			setup: func(t *testing.T) (string, KMSConfig, signature.SignerVerifier) {
				tmpDir, err := os.MkdirTemp("", "cert-test-*")
				require.NoError(t, err)

				outDir := filepath.Join(tmpDir, "out")
				require.NoError(t, os.MkdirAll(outDir, 0755))

				// Create root template
				rootTemplate := filepath.Join(tmpDir, "root.json")
				err = os.WriteFile(rootTemplate, []byte(`{
					"subject": {"commonName": "Test Root CA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 1},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)

				// Create intermediate template
				intermediateTemplate := filepath.Join(tmpDir, "intermediate.json")
				err = os.WriteFile(intermediateTemplate, []byte(`{
					"subject": {"commonName": "Test Intermediate CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 0},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)

				// Create leaf template
				leafTemplate := filepath.Join(tmpDir, "leaf.json")
				err = os.WriteFile(leafTemplate, []byte(`{
					"subject": {"commonName": "Test Leaf"},
					"keyUsage": ["digitalSignature"],
					"extKeyUsage": ["TimeStamping"],
					"basicConstraints": {"isCA": false},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)

				return tmpDir, KMSConfig{
					Type:              "awskms",
					RootKeyID:         "alias/root-key",
					IntermediateKeyID: "alias/intermediate-key",
					LeafKeyID:         "alias/leaf-key",
					Options:           map[string]string{"region": "us-west-2"},
				}, mockSV
			},
		},
		{
			name: "intermediate_cert_creation_error",
			setup: func(t *testing.T) (string, KMSConfig, signature.SignerVerifier) {
				tmpDir, err := os.MkdirTemp("", "cert-test-*")
				require.NoError(t, err)

				outDir := filepath.Join(tmpDir, "out")
				require.NoError(t, os.MkdirAll(outDir, 0755))

				// Create root template
				rootTemplate := filepath.Join(tmpDir, "root.json")
				err = os.WriteFile(rootTemplate, []byte(`{
					"subject": {"commonName": "Test Root CA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 1},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)

				// Create invalid intermediate template
				intermediateTemplate := filepath.Join(tmpDir, "intermediate.json")
				err = os.WriteFile(intermediateTemplate, []byte(`{
					"subject": {"commonName": "Test Intermediate CA"},
					"keyUsage": ["digitalSignature"],
					"basicConstraints": {"isCA": true, "maxPathLen": 0},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)

				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return tmpDir, KMSConfig{
					Type:              "awskms",
					RootKeyID:         "alias/root-key",
					IntermediateKeyID: "alias/intermediate-key",
					LeafKeyID:         "alias/leaf-key",
				}, &mockSignerVerifier{key: key}
			},
			wantError: "template validation error: CA certificate must have certSign key usage",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, config, sv := tt.setup(t)
			defer os.RemoveAll(tmpDir)

			var intermediateKeyID, intermediateTemplate, intermediateCert string
			if strings.Contains(tt.name, "intermediate") {
				intermediateKeyID = config.IntermediateKeyID
				intermediateTemplate = filepath.Join(tmpDir, "intermediate.json")
				intermediateCert = filepath.Join(tmpDir, "out", "intermediate.crt")
			}

			err := CreateCertificates(sv, config,
				filepath.Join(tmpDir, "root.json"),
				filepath.Join(tmpDir, "leaf.json"),
				filepath.Join(tmpDir, "out", "root.crt"),
				filepath.Join(tmpDir, "out", "leaf.crt"),
				intermediateKeyID,
				intermediateTemplate,
				intermediateCert)

			if tt.wantError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			} else {
				require.NoError(t, err)
				// Verify certificates were created
				rootCertPath := filepath.Join(tmpDir, "out", "root.crt")
				leafCertPath := filepath.Join(tmpDir, "out", "leaf.crt")
				require.FileExists(t, rootCertPath)
				require.FileExists(t, leafCertPath)
			}
		})
	}
}

func TestInitKMS(t *testing.T) {
	// Create a temporary credentials file for GCP tests
	tmpDir := t.TempDir()
	gcpCredsFile := filepath.Join(tmpDir, "gcp-credentials.json")
	err := os.WriteFile(gcpCredsFile, []byte(`{
		"type": "service_account",
		"project_id": "test-project",
		"private_key_id": "test-key-id",
		"private_key": "test-private-key",
		"client_email": "test@test-project.iam.gserviceaccount.com",
		"client_id": "test-client-id",
		"auth_uri": "https://accounts.google.com/o/oauth2/auth",
		"token_uri": "https://oauth2.googleapis.com/token",
		"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
		"client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/test@test-project.iam.gserviceaccount.com"
	}`), 0600)
	require.NoError(t, err)

	tests := []struct {
		name    string
		config  KMSConfig
		wantErr string
	}{
		{
			name: "aws_kms_valid_config",
			config: KMSConfig{
				Type:              "awskms",
				RootKeyID:         "alias/test-root-key",
				IntermediateKeyID: "alias/test-intermediate-key",
				LeafKeyID:         "alias/test-leaf-key",
				Options:           map[string]string{"aws-region": "us-west-2"},
			},
		},
		{
			name: "azure_kms_valid_config",
			config: KMSConfig{
				Type:              "azurekms",
				RootKeyID:         "azurekms:name=test-root-key;vault=test-vault",
				IntermediateKeyID: "azurekms:name=test-intermediate-key;vault=test-vault",
				LeafKeyID:         "azurekms:name=test-leaf-key;vault=test-vault",
				Options:           map[string]string{"azure-tenant-id": "test-tenant"},
			},
		},
		{
			name: "gcp_kms_valid_config",
			config: KMSConfig{
				Type:              "gcpkms",
				RootKeyID:         "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1",
				IntermediateKeyID: "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/test-intermediate-key/cryptoKeyVersions/1",
				LeafKeyID:         "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/test-leaf-key/cryptoKeyVersions/1",
				Options:           map[string]string{"gcp-credentials-file": gcpCredsFile},
			},
		},
		{
			name: "hashivault_kms_valid_config",
			config: KMSConfig{
				Type:              "hashivault",
				RootKeyID:         "test-key",
				IntermediateKeyID: "test-intermediate-key",
				LeafKeyID:         "test-leaf-key",
				Options:           map[string]string{"vault-token": "test-token", "vault-address": "http://localhost:8200"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			_, err := InitKMS(ctx, tt.config)
			if tt.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCreateCertificatesWithoutIntermediate(t *testing.T) {
	// Create temp dir for test files
	tmpDir := t.TempDir()
	outDir := filepath.Join(tmpDir, "out")
	require.NoError(t, os.MkdirAll(outDir, 0755))

	// Create test templates
	rootTemplate := `{
		"subject": {
			"commonName": "Test Root CA"
		},
		"issuer": {
			"commonName": "Test Root CA"
		},
		"notBefore": "2024-01-01T00:00:00Z",
		"notAfter": "2034-01-01T00:00:00Z",
		"keyUsage": ["certSign"],
		"basicConstraints": {
			"isCA": true
		}
	}`

	leafTemplate := `{
		"subject": {
			"commonName": "Test Leaf"
		},
		"notBefore": "2024-01-01T00:00:00Z",
		"notAfter": "2034-01-01T00:00:00Z",
		"keyUsage": ["digitalSignature"]
	}`

	rootTemplatePath := filepath.Join(tmpDir, "root.json")
	leafTemplatePath := filepath.Join(tmpDir, "leaf.json")
	require.NoError(t, os.WriteFile(rootTemplatePath, []byte(rootTemplate), 0644))
	require.NoError(t, os.WriteFile(leafTemplatePath, []byte(leafTemplate), 0644))

	rootCertPath := filepath.Join(outDir, "root.crt")
	leafCertPath := filepath.Join(outDir, "leaf.crt")

	// Create mock signer
	mockSigner := &mockSignerVerifier{
		err: fmt.Errorf("error getting root public key: getting public key: operation error KMS: GetPublicKey"),
	}

	config := KMSConfig{
		Type:              "awskms",
		RootKeyID:         "alias/test-root-key",
		IntermediateKeyID: "alias/test-intermediate-key",
		LeafKeyID:         "alias/test-leaf-key",
		Options:           map[string]string{"region": "us-west-2"},
	}

	err := CreateCertificates(mockSigner, config, rootTemplatePath, leafTemplatePath, rootCertPath, leafCertPath, "", "", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "error getting root public key: getting public key: operation error KMS: GetPublicKey")
}

func TestCreateCertificatesLeafErrors(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cert-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	rootTemplate := filepath.Join(tmpDir, "root.json")
	err = os.WriteFile(rootTemplate, []byte(`{
		"subject": {"commonName": "Test Root CA"},
		"issuer": {"commonName": "Test Root CA"},
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {"isCA": true, "maxPathLen": 1},
		"notBefore": "2024-01-01T00:00:00Z",
		"notAfter": "2025-01-01T00:00:00Z"
	}`), 0600)
	require.NoError(t, err)

	leafTemplate := filepath.Join(tmpDir, "leaf.json")
	err = os.WriteFile(leafTemplate, []byte(`{invalid json`), 0600)
	require.NoError(t, err)

	outDir := filepath.Join(tmpDir, "out")
	require.NoError(t, os.MkdirAll(outDir, 0755))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	config := KMSConfig{
		Type:      "awskms",
		RootKeyID: "awskms:///arn:aws:kms:us-west-2:123456789012:key/root-key",
		LeafKeyID: "arn:aws:kms:us-west-2:123456789012:key/leaf-key",
		Options:   map[string]string{"region": "us-west-2"},
	}

	err = CreateCertificates(&mockSignerVerifier{key: key}, config,
		rootTemplate,
		leafTemplate,
		filepath.Join(outDir, "root.crt"),
		filepath.Join(outDir, "leaf.crt"),
		"", // No intermediate key ID
		"", // No intermediate template
		"") // No intermediate cert path

	require.Error(t, err)
	assert.Contains(t, err.Error(), "error parsing leaf template")
}

func TestCreateCertificatesWithErrors(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T) (string, KMSConfig, signature.SignerVerifier)
		wantError string
	}{
		{
			name: "root_cert_creation_error",
			setup: func(t *testing.T) (string, KMSConfig, signature.SignerVerifier) {
				tmpDir, err := os.MkdirTemp("", "cert-test-*")
				require.NoError(t, err)

				rootTemplate := filepath.Join(tmpDir, "root.json")
				err = os.WriteFile(rootTemplate, []byte(`{
					"subject": {"commonName": "Test Root CA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 1},
					"notBefore": "invalid-time",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)

				outDir := filepath.Join(tmpDir, "out")
				require.NoError(t, os.MkdirAll(outDir, 0755))

				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)

				return tmpDir, KMSConfig{
					Type:      "awskms",
					RootKeyID: "awskms:///arn:aws:kms:us-west-2:123456789012:key/root-key",
					LeafKeyID: "arn:aws:kms:us-west-2:123456789012:key/leaf-key",
					Options:   map[string]string{"region": "us-west-2"},
				}, &mockSignerVerifier{key: key}
			},
			wantError: "error parsing root template: template validation error: invalid notBefore time format",
		},
		{
			name: "root_cert_sign_error",
			setup: func(t *testing.T) (string, KMSConfig, signature.SignerVerifier) {
				tmpDir, err := os.MkdirTemp("", "cert-test-*")
				require.NoError(t, err)

				rootTemplate := filepath.Join(tmpDir, "root.json")
				err = os.WriteFile(rootTemplate, []byte(`{
					"subject": {"commonName": "Test Root CA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 1},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)

				outDir := filepath.Join(tmpDir, "out")
				require.NoError(t, os.MkdirAll(outDir, 0755))

				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)

				return tmpDir, KMSConfig{
					Type:      "awskms",
					RootKeyID: "awskms:///arn:aws:kms:us-west-2:123456789012:key/root-key",
					LeafKeyID: "arn:aws:kms:us-west-2:123456789012:key/leaf-key",
					Options:   map[string]string{"region": "us-west-2"},
				}, &mockSignerVerifier{key: key, err: fmt.Errorf("signing error")}
			},
			wantError: "error getting root public key: signing error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, config, sv := tt.setup(t)
			defer os.RemoveAll(tmpDir)

			err := CreateCertificates(sv, config,
				filepath.Join(tmpDir, "root.json"),
				filepath.Join(tmpDir, "leaf.json"),
				filepath.Join(tmpDir, "out", "root.crt"),
				filepath.Join(tmpDir, "out", "leaf.crt"),
				"",
				"",
				"")

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantError)
		})
	}
}

func TestWriteCertificateToFileWithErrors(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T) (*x509.Certificate, string)
		wantError string
	}{
		{
			name: "file_write_error",
			setup: func(t *testing.T) (*x509.Certificate, string) {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)

				template := &x509.Certificate{
					SerialNumber: big.NewInt(1),
					Subject: pkix.Name{
						CommonName: "Test CA",
					},
					NotBefore:             time.Now(),
					NotAfter:              time.Now().Add(time.Hour * 24 * 365),
					KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
					BasicConstraintsValid: true,
					IsCA:                  true,
				}

				cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
				require.NoError(t, err)

				parsedCert, err := x509.ParseCertificate(cert)
				require.NoError(t, err)

				// Create a read-only directory to cause a write error
				tmpDir, err := os.MkdirTemp("", "cert-test-*")
				require.NoError(t, err)
				require.NoError(t, os.Chmod(tmpDir, 0500))
				certPath := filepath.Join(tmpDir, "cert.crt")

				return parsedCert, certPath
			},
			wantError: "failed to create file",
		},
		{
			name: "invalid_cert_path",
			setup: func(t *testing.T) (*x509.Certificate, string) {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)

				template := &x509.Certificate{
					SerialNumber: big.NewInt(1),
					Subject: pkix.Name{
						CommonName: "Test CA",
					},
					NotBefore:             time.Now(),
					NotAfter:              time.Now().Add(time.Hour * 24 * 365),
					KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
					BasicConstraintsValid: true,
					IsCA:                  true,
				}

				cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
				require.NoError(t, err)

				parsedCert, err := x509.ParseCertificate(cert)
				require.NoError(t, err)

				return parsedCert, "/nonexistent/directory/cert.crt"
			},
			wantError: "failed to create file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, path := tt.setup(t)
			if strings.HasPrefix(path, "/var") || strings.HasPrefix(path, "/tmp") {
				defer os.RemoveAll(filepath.Dir(path))
			}

			err := WriteCertificateToFile(cert, path)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantError)
		})
	}
}

func TestValidateTemplateWithInvalidExtKeyUsage(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cert-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	templateFile := filepath.Join(tmpDir, "template.json")
	err = os.WriteFile(templateFile, []byte(`{
		"subject": {"commonName": "Test TSA"},
		"issuer": {"commonName": "Test TSA"},
		"keyUsage": ["digitalSignature"],
		"basicConstraints": {"isCA": true},
		"extensions": [
			{
				"id": "2.5.29.37",
				"critical": true,
				"value": "MCQwIgYDVR0lBBswGQYIKwYBBQUHAwgGDSsGAQQBgjcUAgICAf8="
			}
		],
		"notBefore": "2024-01-01T00:00:00Z",
		"notAfter": "2025-01-01T00:00:00Z"
	}`), 0600)
	require.NoError(t, err)

	parent := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "Parent CA",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	template, err := ParseTemplate(templateFile, parent)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CA certificate must have certSign key usage")
	assert.Nil(t, template)
}

func TestCreateCertificatesWithInvalidIntermediateKey(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cert-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create valid root template
	rootTemplate := filepath.Join(tmpDir, "root.json")
	err = os.WriteFile(rootTemplate, []byte(`{
		"subject": {"commonName": "Test Root CA"},
		"issuer": {"commonName": "Test Root CA"},
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {"isCA": true, "maxPathLen": 1},
		"notBefore": "2024-01-01T00:00:00Z",
		"notAfter": "2025-01-01T00:00:00Z"
	}`), 0600)
	require.NoError(t, err)

	// Create valid leaf template
	leafTemplate := filepath.Join(tmpDir, "leaf.json")
	err = os.WriteFile(leafTemplate, []byte(`{
		"subject": {"commonName": "Test Leaf"},
		"keyUsage": ["digitalSignature"],
		"extKeyUsage": ["TimeStamping"],
		"basicConstraints": {"isCA": false},
		"notBefore": "2024-01-01T00:00:00Z",
		"notAfter": "2025-01-01T00:00:00Z"
	}`), 0600)
	require.NoError(t, err)

	// Create valid intermediate template
	intermediateTemplate := filepath.Join(tmpDir, "intermediate.json")
	err = os.WriteFile(intermediateTemplate, []byte(`{
		"subject": {"commonName": "Test Intermediate CA"},
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {"isCA": true, "maxPathLen": 0},
		"notBefore": "2024-01-01T00:00:00Z",
		"notAfter": "2025-01-01T00:00:00Z"
	}`), 0600)
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Test with invalid intermediate key ID format
	err = CreateCertificates(
		&mockSignerVerifier{key: key},
		KMSConfig{
			Type:              "awskms",
			RootKeyID:         "arn:aws:kms:us-west-2:123456789012:key/test-key",
			IntermediateKeyID: "invalid-intermediate-key",
			LeafKeyID:         "arn:aws:kms:us-west-2:123456789012:key/test-key",
			Options:           map[string]string{"aws-region": "us-west-2"},
		},
		rootTemplate,
		leafTemplate,
		filepath.Join(tmpDir, "root.crt"),
		filepath.Join(tmpDir, "leaf.crt"),
		"invalid-intermediate-key",
		intermediateTemplate,
		filepath.Join(tmpDir, "intermediate.crt"),
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "error initializing intermediate KMS: invalid KMS configuration: awskms RootKeyID must start with 'arn:aws:kms:' or 'alias/'")
}

func TestCreateCertificatesWithInvalidLeafKey(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cert-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create valid root template
	rootTemplate := filepath.Join(tmpDir, "root.json")
	err = os.WriteFile(rootTemplate, []byte(`{
		"subject": {"commonName": "Test Root CA"},
		"issuer": {"commonName": "Test Root CA"},
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {"isCA": true, "maxPathLen": 1},
		"notBefore": "2024-01-01T00:00:00Z",
		"notAfter": "2025-01-01T00:00:00Z"
	}`), 0600)
	require.NoError(t, err)

	// Create valid leaf template
	leafTemplate := filepath.Join(tmpDir, "leaf.json")
	err = os.WriteFile(leafTemplate, []byte(`{
		"subject": {"commonName": "Test Leaf"},
		"keyUsage": ["digitalSignature"],
		"extKeyUsage": ["TimeStamping"],
		"basicConstraints": {"isCA": false},
		"notBefore": "2024-01-01T00:00:00Z",
		"notAfter": "2025-01-01T00:00:00Z"
	}`), 0600)
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Test with invalid leaf key ID format
	err = CreateCertificates(
		&mockSignerVerifier{key: key},
		KMSConfig{
			Type:      "awskms",
			RootKeyID: "arn:aws:kms:us-west-2:123456789012:key/test-key",
			LeafKeyID: "invalid-leaf-key",
		},
		rootTemplate,
		leafTemplate,
		filepath.Join(tmpDir, "root.crt"),
		filepath.Join(tmpDir, "leaf.crt"),
		"",
		"",
		"",
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "error initializing leaf KMS")
}

func TestCreateCertificatesWithInvalidRootCert(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cert-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create invalid root template (missing required fields)
	rootTemplate := filepath.Join(tmpDir, "root.json")
	err = os.WriteFile(rootTemplate, []byte(`{
		"subject": {},
		"issuer": {},
		"notBefore": "2024-01-01T00:00:00Z",
		"notAfter": "2025-01-01T00:00:00Z"
	}`), 0600)
	require.NoError(t, err)

	// Create valid leaf template
	leafTemplate := filepath.Join(tmpDir, "leaf.json")
	err = os.WriteFile(leafTemplate, []byte(`{
		"subject": {"commonName": "Test Leaf"},
		"keyUsage": ["digitalSignature"],
		"extKeyUsage": ["TimeStamping"],
		"basicConstraints": {"isCA": false},
		"notBefore": "2024-01-01T00:00:00Z",
		"notAfter": "2025-01-01T00:00:00Z"
	}`), 0600)
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	err = CreateCertificates(
		&mockSignerVerifier{key: key},
		KMSConfig{
			Type:      "awskms",
			RootKeyID: "arn:aws:kms:us-west-2:123456789012:key/test-key",
			LeafKeyID: "arn:aws:kms:us-west-2:123456789012:key/test-key",
		},
		rootTemplate,
		leafTemplate,
		filepath.Join(tmpDir, "root.crt"),
		filepath.Join(tmpDir, "leaf.crt"),
		"",
		"",
		"",
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "subject.commonName cannot be empty")
}

func TestCreateCertificatesWithInvalidCertPath(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cert-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create valid templates
	rootTemplate := filepath.Join(tmpDir, "root.json")
	err = os.WriteFile(rootTemplate, []byte(`{
		"subject": {"commonName": "Test Root CA"},
		"issuer": {"commonName": "Test Root CA"},
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {"isCA": true, "maxPathLen": 1},
		"notBefore": "2024-01-01T00:00:00Z",
		"notAfter": "2025-01-01T00:00:00Z"
	}`), 0600)
	require.NoError(t, err)

	leafTemplate := filepath.Join(tmpDir, "leaf.json")
	err = os.WriteFile(leafTemplate, []byte(`{
		"subject": {"commonName": "Test Leaf"},
		"keyUsage": ["digitalSignature"],
		"extKeyUsage": ["TimeStamping"],
		"basicConstraints": {"isCA": false},
		"notBefore": "2024-01-01T00:00:00Z",
		"notAfter": "2025-01-01T00:00:00Z"
	}`), 0600)
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create a directory where a file should be and make it read-only
	invalidPath := filepath.Join(tmpDir, "invalid")
	err = os.MkdirAll(invalidPath, 0444) // Changed permissions to read-only
	require.NoError(t, err)

	err = CreateCertificates(
		&mockSignerVerifier{key: key},
		KMSConfig{
			Type:      "awskms",
			RootKeyID: "arn:aws:kms:us-west-2:123456789012:key/test-key",
			LeafKeyID: "arn:aws:kms:us-west-2:123456789012:key/test-key",
		},
		rootTemplate,
		leafTemplate,
		filepath.Join(invalidPath, "root.crt"),
		filepath.Join(invalidPath, "leaf.crt"),
		"",
		"",
		"",
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "error writing root certificate")
}

func TestWriteCertificateToFileWithPEMError(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cert-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create a directory where a file should be to cause a write error
	certPath := filepath.Join(tmpDir, "cert.pem")
	err = os.MkdirAll(certPath, 0755) // Create a directory instead of a file
	require.NoError(t, err)

	// Create a valid certificate
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)

	// Try to write to a path that is a directory, which should fail
	err = WriteCertificateToFile(cert, certPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create file")
}

func TestCreateCertificatesWithInvalidRootKey(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cert-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create valid templates
	rootTemplate := filepath.Join(tmpDir, "root.json")
	err = os.WriteFile(rootTemplate, []byte(`{
		"subject": {"commonName": "Test Root CA"},
		"issuer": {"commonName": "Test Root CA"},
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {"isCA": true, "maxPathLen": 1},
		"notBefore": "2024-01-01T00:00:00Z",
		"notAfter": "2025-01-01T00:00:00Z"
	}`), 0600)
	require.NoError(t, err)

	leafTemplate := filepath.Join(tmpDir, "leaf.json")
	err = os.WriteFile(leafTemplate, []byte(`{
		"subject": {"commonName": "Test Leaf"},
		"keyUsage": ["digitalSignature"],
		"extKeyUsage": ["TimeStamping"],
		"basicConstraints": {"isCA": false},
		"notBefore": "2024-01-01T00:00:00Z",
		"notAfter": "2025-01-01T00:00:00Z"
	}`), 0600)
	require.NoError(t, err)

	// Test with signing error
	err = CreateCertificates(
		&mockSignerVerifier{key: nil, err: fmt.Errorf("signing error")},
		KMSConfig{
			Type:      "awskms",
			RootKeyID: "arn:aws:kms:us-west-2:123456789012:key/test-key",
			LeafKeyID: "arn:aws:kms:us-west-2:123456789012:key/test-key",
		},
		rootTemplate,
		leafTemplate,
		filepath.Join(tmpDir, "root.crt"),
		filepath.Join(tmpDir, "leaf.crt"),
		"",
		"",
		"",
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "error getting root public key: signing error")
}

func TestCreateCertificatesWithInvalidLeafTemplate(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T) (string, KMSConfig, signature.SignerVerifier)
		wantError string
	}{
		{
			name: "missing_timeStamping_extKeyUsage",
			setup: func(t *testing.T) (string, KMSConfig, signature.SignerVerifier) {
				tmpDir := t.TempDir()

				// Create test templates
				rootTemplate := `{
					"subject": {
						"commonName": "Test Root CA"
					},
					"issuer": {
						"commonName": "Test Root CA"
					},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2034-01-01T00:00:00Z",
					"keyUsage": ["certSign"],
					"basicConstraints": {
						"isCA": true
					}
				}`

				leafTemplate := `{
					"subject": {
						"commonName": "Test Leaf"
					},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2034-01-01T00:00:00Z",
					"keyUsage": ["digitalSignature"]
				}`

				rootTemplatePath := filepath.Join(tmpDir, "root.json")
				leafTemplatePath := filepath.Join(tmpDir, "leaf.json")
				require.NoError(t, os.WriteFile(rootTemplatePath, []byte(rootTemplate), 0644))
				require.NoError(t, os.WriteFile(leafTemplatePath, []byte(leafTemplate), 0644))

				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)

				return tmpDir, KMSConfig{
					Type:              "awskms",
					RootKeyID:         "arn:aws:kms:us-west-2:123456789012:key/test-key",
					IntermediateKeyID: "arn:aws:kms:us-west-2:123456789012:key/intermediate-key",
					LeafKeyID:         "invalid-key",
					Options:           map[string]string{"aws-region": "us-west-2"},
				}, &mockSignerVerifier{key: key}
			},
			wantError: "error initializing leaf KMS: invalid KMS configuration: awskms RootKeyID must start with 'arn:aws:kms:' or 'alias/'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, config, signer := tt.setup(t)
			rootCertPath := filepath.Join(tmpDir, "root.crt")
			err := CreateCertificates(signer, config, filepath.Join(tmpDir, "root.json"), filepath.Join(tmpDir, "leaf.json"), rootCertPath, "", "", "", "")
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantError)
		})
	}
}

func TestCreateCertificatesWithIntermediateErrors(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T) (string, KMSConfig, signature.SignerVerifier)
		wantError string
	}{
		{
			name: "intermediate_template_parse_error",
			setup: func(t *testing.T) (string, KMSConfig, signature.SignerVerifier) {
				tmpDir, err := os.MkdirTemp("", "cert-test-*")
				require.NoError(t, err)

				outDir := filepath.Join(tmpDir, "out")
				require.NoError(t, os.MkdirAll(outDir, 0755))

				rootTemplate := filepath.Join(tmpDir, "root.json")
				err = os.WriteFile(rootTemplate, []byte(`{
					"subject": {"commonName": "Test Root CA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 1},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)

				leafTemplate := filepath.Join(tmpDir, "leaf.json")
				err = os.WriteFile(leafTemplate, []byte(`{
					"subject": {"commonName": "Test Leaf"},
					"keyUsage": ["digitalSignature"],
					"extKeyUsage": ["TimeStamping"],
					"basicConstraints": {"isCA": false},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)

				intermediateTemplate := filepath.Join(tmpDir, "intermediate.json")
				err = os.WriteFile(intermediateTemplate, []byte(`{invalid json`), 0600)
				require.NoError(t, err)

				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)

				return tmpDir, KMSConfig{
					Type:              "awskms",
					RootKeyID:         "arn:aws:kms:us-west-2:123456789012:key/root-key",
					IntermediateKeyID: "arn:aws:kms:us-west-2:123456789012:key/intermediate-key",
					LeafKeyID:         "arn:aws:kms:us-west-2:123456789012:key/leaf-key",
				}, &mockSignerVerifier{key: key}
			},
			wantError: "error parsing intermediate template",
		},
		{
			name: "intermediate_cert_write_error",
			setup: func(t *testing.T) (string, KMSConfig, signature.SignerVerifier) {
				tmpDir, err := os.MkdirTemp("", "cert-test-*")
				require.NoError(t, err)

				outDir := filepath.Join(tmpDir, "out")
				require.NoError(t, os.MkdirAll(outDir, 0755))

				rootTemplate := filepath.Join(tmpDir, "root.json")
				err = os.WriteFile(rootTemplate, []byte(`{
					"subject": {"commonName": "Test Root CA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 1},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)

				leafTemplate := filepath.Join(tmpDir, "leaf.json")
				err = os.WriteFile(leafTemplate, []byte(`{
					"subject": {"commonName": "Test Leaf"},
					"keyUsage": ["digitalSignature"],
					"extKeyUsage": ["TimeStamping"],
					"basicConstraints": {"isCA": false},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)

				intermediateTemplate := filepath.Join(tmpDir, "intermediate.json")
				err = os.WriteFile(intermediateTemplate, []byte(`{
					"subject": {"commonName": "Test Intermediate CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 0},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)

				// Create a directory where the intermediate cert file should be
				intermediateCertDir := filepath.Join(outDir, "intermediate.crt")
				require.NoError(t, os.MkdirAll(intermediateCertDir, 0755))

				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)

				return tmpDir, KMSConfig{
					Type:              "awskms",
					RootKeyID:         "arn:aws:kms:us-west-2:123456789012:key/root-key",
					IntermediateKeyID: "arn:aws:kms:us-west-2:123456789012:key/intermediate-key",
					LeafKeyID:         "arn:aws:kms:us-west-2:123456789012:key/leaf-key",
				}, &mockSignerVerifier{key: key}
			},
			wantError: "error initializing intermediate KMS",
		},
		{
			name: "leaf_cert_with_intermediate_error",
			setup: func(t *testing.T) (string, KMSConfig, signature.SignerVerifier) {
				tmpDir, err := os.MkdirTemp("", "cert-test-*")
				require.NoError(t, err)

				outDir := filepath.Join(tmpDir, "out")
				require.NoError(t, os.MkdirAll(outDir, 0755))

				rootTemplate := filepath.Join(tmpDir, "root.json")
				err = os.WriteFile(rootTemplate, []byte(`{
					"subject": {"commonName": "Test Root CA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 1},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)

				leafTemplate := filepath.Join(tmpDir, "leaf.json")
				err = os.WriteFile(leafTemplate, []byte(`{
					"subject": {"commonName": "Test Leaf"},
					"keyUsage": ["digitalSignature"],
					"extKeyUsage": ["TimeStamping"],
					"basicConstraints": {"isCA": false},
					"notBefore": "invalid-time",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)

				intermediateTemplate := filepath.Join(tmpDir, "intermediate.json")
				err = os.WriteFile(intermediateTemplate, []byte(`{
					"subject": {"commonName": "Test Intermediate CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 0},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)

				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)

				return tmpDir, KMSConfig{
					Type:              "awskms",
					RootKeyID:         "arn:aws:kms:us-west-2:123456789012:key/root-key",
					IntermediateKeyID: "arn:aws:kms:us-west-2:123456789012:key/intermediate-key",
					LeafKeyID:         "arn:aws:kms:us-west-2:123456789012:key/leaf-key",
				}, &mockSignerVerifier{key: key}
			},
			wantError: "error initializing intermediate KMS",
		},
		{
			name: "invalid_intermediate_template_validation",
			setup: func(t *testing.T) (string, KMSConfig, signature.SignerVerifier) {
				tmpDir, err := os.MkdirTemp("", "cert-test-*")
				require.NoError(t, err)

				outDir := filepath.Join(tmpDir, "out")
				require.NoError(t, os.MkdirAll(outDir, 0755))

				rootTemplate := filepath.Join(tmpDir, "root.json")
				err = os.WriteFile(rootTemplate, []byte(`{
					"subject": {"commonName": "Test Root CA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 1},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)

				leafTemplate := filepath.Join(tmpDir, "leaf.json")
				err = os.WriteFile(leafTemplate, []byte(`{
					"subject": {"commonName": "Test Leaf"},
					"keyUsage": ["digitalSignature"],
					"extKeyUsage": ["TimeStamping"],
					"basicConstraints": {"isCA": false},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)

				intermediateTemplate := filepath.Join(tmpDir, "intermediate.json")
				err = os.WriteFile(intermediateTemplate, []byte(`{
					"subject": {"commonName": "Test Intermediate CA"},
					"keyUsage": ["digitalSignature"],
					"basicConstraints": {"isCA": true, "maxPathLen": 0},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)

				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)

				return tmpDir, KMSConfig{
					Type:              "awskms",
					RootKeyID:         "arn:aws:kms:us-west-2:123456789012:key/root-key",
					IntermediateKeyID: "arn:aws:kms:us-west-2:123456789012:key/intermediate-key",
					LeafKeyID:         "arn:aws:kms:us-west-2:123456789012:key/leaf-key",
				}, &mockSignerVerifier{key: key}
			},
			wantError: "error parsing intermediate template: template validation error: CA certificate must have certSign key usage",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, config, sv := tt.setup(t)
			defer os.RemoveAll(tmpDir)

			err := CreateCertificates(sv, config,
				filepath.Join(tmpDir, "root.json"),
				filepath.Join(tmpDir, "leaf.json"),
				filepath.Join(tmpDir, "out", "root.crt"),
				filepath.Join(tmpDir, "out", "leaf.crt"),
				config.IntermediateKeyID,
				filepath.Join(tmpDir, "intermediate.json"),
				filepath.Join(tmpDir, "out", "intermediate.crt"))

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantError)
		})
	}
}
