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
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/x509util"
)

// mockKMSProvider is a mock implementation of apiv1.KeyManager
type mockKMSProvider struct {
	name    string
	keys    map[string]*ecdsa.PrivateKey
	signers map[string]crypto.Signer
}

func newMockKMSProvider() *mockKMSProvider {
	m := &mockKMSProvider{
		name:    "test",
		keys:    make(map[string]*ecdsa.PrivateKey),
		signers: make(map[string]crypto.Signer),
	}

	// Pre-create test keys
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	intermediateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	m.keys["root-key"] = rootKey
	m.keys["intermediate-key"] = intermediateKey
	m.keys["leaf-key"] = leafKey

	return m
}

func (m *mockKMSProvider) CreateKey(*apiv1.CreateKeyRequest) (*apiv1.CreateKeyResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockKMSProvider) CreateSigner(req *apiv1.CreateSignerRequest) (crypto.Signer, error) {
	key, ok := m.keys[req.SigningKey]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", req.SigningKey)
	}
	m.signers[req.SigningKey] = key
	return key, nil
}

func (m *mockKMSProvider) GetPublicKey(req *apiv1.GetPublicKeyRequest) (crypto.PublicKey, error) {
	key, ok := m.keys[req.Name]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", req.Name)
	}
	return key.Public(), nil
}

func (m *mockKMSProvider) Close() error {
	return nil
}

func TestValidateKMSConfig(t *testing.T) {
	tests := []struct {
		name      string
		config    KMSConfig
		wantError string
	}{
		{
			name: "empty KMS type",
			config: KMSConfig{
				RootKeyID: "key-id",
			},
			wantError: "KMS type cannot be empty",
		},
		{
			name: "missing key IDs",
			config: KMSConfig{
				Type: "awskms",
			},
			wantError: "at least one of RootKeyID or LeafKeyID must be specified",
		},
		{
			name: "AWS KMS missing region",
			config: KMSConfig{
				Type:      "awskms",
				RootKeyID: "arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab",
			},
			wantError: "region is required for AWS KMS",
		},
		{
			name: "AWS KMS invalid root key ID",
			config: KMSConfig{
				Type:      "awskms",
				Region:    "us-west-2",
				RootKeyID: "invalid-key-id",
			},
			wantError: "awskms RootKeyID must start with 'arn:aws:kms:' or 'alias/'",
		},
		{
			name: "AWS KMS invalid intermediate key ID",
			config: KMSConfig{
				Type:              "awskms",
				Region:            "us-west-2",
				RootKeyID:         "arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab",
				IntermediateKeyID: "invalid-key-id",
			},
			wantError: "awskms IntermediateKeyID must start with 'arn:aws:kms:' or 'alias/'",
		},
		{
			name: "AWS KMS invalid leaf key ID",
			config: KMSConfig{
				Type:      "awskms",
				Region:    "us-west-2",
				LeafKeyID: "invalid-key-id",
			},
			wantError: "awskms LeafKeyID must start with 'arn:aws:kms:' or 'alias/'",
		},
		{
			name: "GCP KMS invalid root key ID",
			config: KMSConfig{
				Type:      "gcpkms",
				RootKeyID: "invalid-key-id",
			},
			wantError: "gcpkms RootKeyID must start with 'projects/'",
		},
		{
			name: "GCP KMS invalid intermediate key ID",
			config: KMSConfig{
				Type:              "gcpkms",
				RootKeyID:         "projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/my-key",
				IntermediateKeyID: "invalid-key-id",
			},
			wantError: "gcpkms IntermediateKeyID must start with 'projects/'",
		},
		{
			name: "GCP KMS invalid leaf key ID",
			config: KMSConfig{
				Type:      "gcpkms",
				LeafKeyID: "invalid-key-id",
			},
			wantError: "gcpkms LeafKeyID must start with 'projects/'",
		},
		{
			name: "GCP KMS missing required parts",
			config: KMSConfig{
				Type:      "gcpkms",
				RootKeyID: "projects/my-project",
			},
			wantError: "invalid gcpkms key format",
		},
		{
			name: "Azure KMS missing tenant ID",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "azurekms:name=my-key;vault=my-vault",
			},
			wantError: "tenant-id is required for Azure KMS",
		},
		{
			name: "Azure KMS invalid root key ID prefix",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "invalid-key-id",
				Options: map[string]string{
					"tenant-id": "tenant-id",
				},
			},
			wantError: "azurekms RootKeyID must start with 'azurekms:name='",
		},
		{
			name: "Azure KMS missing vault parameter",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "azurekms:name=my-key",
				Options: map[string]string{
					"tenant-id": "tenant-id",
				},
			},
			wantError: "azurekms RootKeyID must contain ';vault=' parameter",
		},
		{
			name: "Azure KMS invalid intermediate key ID",
			config: KMSConfig{
				Type:              "azurekms",
				RootKeyID:         "azurekms:name=my-key;vault=my-vault",
				IntermediateKeyID: "invalid-key-id",
				Options: map[string]string{
					"tenant-id": "tenant-id",
				},
			},
			wantError: "azurekms IntermediateKeyID must start with 'azurekms:name='",
		},
		{
			name: "Azure KMS invalid leaf key ID",
			config: KMSConfig{
				Type:      "azurekms",
				LeafKeyID: "invalid-key-id",
				Options: map[string]string{
					"tenant-id": "tenant-id",
				},
			},
			wantError: "azurekms LeafKeyID must start with 'azurekms:name='",
		},
		{
			name: "unsupported KMS type",
			config: KMSConfig{
				Type:      "invalidkms",
				RootKeyID: "key-id",
			},
			wantError: "unsupported KMS type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKMSConfig(tt.config)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantError)
		})
	}

	// Test valid configurations
	validConfigs := []KMSConfig{
		{
			Type:      "awskms",
			Region:    "us-west-2",
			RootKeyID: "arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab",
		},
		{
			Type:      "awskms",
			Region:    "us-west-2",
			LeafKeyID: "alias/my-key",
		},
		{
			Type:      "gcpkms",
			RootKeyID: "projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/my-key",
		},
		{
			Type:      "azurekms",
			RootKeyID: "azurekms:name=my-key;vault=my-vault",
			Options: map[string]string{
				"tenant-id": "tenant-id",
			},
		},
	}

	for _, config := range validConfigs {
		t.Run(fmt.Sprintf("valid %s config", config.Type), func(t *testing.T) {
			err := ValidateKMSConfig(config)
			require.NoError(t, err)
		})
	}
}

func TestValidateTemplatePath(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "template-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create a valid JSON file
	validPath := filepath.Join(tmpDir, "valid.json")
	err = os.WriteFile(validPath, []byte("{}"), 0600)
	require.NoError(t, err)

	// Create a non-JSON file
	nonJSONPath := filepath.Join(tmpDir, "invalid.txt")
	err = os.WriteFile(nonJSONPath, []byte("{}"), 0600)
	require.NoError(t, err)

	tests := []struct {
		name      string
		path      string
		wantError string
	}{
		{
			name: "valid JSON file",
			path: validPath,
		},
		{
			name:      "non-existent file",
			path:      "/nonexistent/template.json",
			wantError: "template not found",
		},
		{
			name:      "wrong extension",
			path:      nonJSONPath,
			wantError: "template file must have .json extension",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTemplatePath(tt.path)
			if tt.wantError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestWriteCertificateToFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cert-write-test-*")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	// Create a key pair
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create a certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Cert",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		PublicKeyAlgorithm:    x509.ECDSA,
	}

	// Create a self-signed certificate
	cert, err := x509util.CreateCertificate(template, template, key.Public(), key)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		testFile := filepath.Join(tmpDir, "test-cert.pem")
		err = WriteCertificateToFile(cert, testFile)
		require.NoError(t, err)

		content, err := os.ReadFile(testFile)
		require.NoError(t, err)

		block, _ := pem.Decode(content)
		require.NotNil(t, block)
		assert.Equal(t, "CERTIFICATE", block.Type)

		parsedCert, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)
		assert.Equal(t, "Test Cert", parsedCert.Subject.CommonName)
	})

	t.Run("error writing to file", func(t *testing.T) {
		// Try to write to a non-existent directory
		testFile := filepath.Join(tmpDir, "nonexistent", "test-cert.pem")
		err = WriteCertificateToFile(cert, testFile)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create file")
	})
}

func TestCreateCertificates(t *testing.T) {
	rootContent := `{
		"subject": {
			"country": ["US"],
			"organization": ["Sigstore"],
			"organizationalUnit": ["Timestamp Authority Root CA"],
			"commonName": "https://tsa.com"
		},
		"issuer": {
			"commonName": "https://tsa.com"
		},
		"notBefore": "2024-01-01T00:00:00Z",
		"notAfter": "2034-01-01T00:00:00Z",
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 1
		},
		"keyUsage": [
			"certSign",
			"crlSign"
		]
	}`

	leafContent := `{
		"subject": {
			"country": ["US"],
			"organization": ["Sigstore"],
			"organizationalUnit": ["Timestamp Authority"],
			"commonName": "https://tsa.com"
		},
		"issuer": {
			"commonName": "https://tsa.com"
		},
		"notBefore": "2024-01-01T00:00:00Z",
		"notAfter": "2034-01-01T00:00:00Z",
		"basicConstraints": {
			"isCA": false
		},
		"keyUsage": [
			"digitalSignature"
		],
		"extKeyUsage": [
			"timeStamping"
		]
	}`

	t.Run("TSA without intermediate", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "cert-test-tsa-*")
		require.NoError(t, err)
		t.Cleanup(func() { os.RemoveAll(tmpDir) })

		km := newMockKMSProvider()
		config := KMSConfig{
			Type:      "mockkms",
			RootKeyID: "root-key",
			LeafKeyID: "leaf-key",
			Options:   make(map[string]string),
		}

		rootTmplPath := filepath.Join(tmpDir, "root-template.json")
		leafTmplPath := filepath.Join(tmpDir, "leaf-template.json")
		rootCertPath := filepath.Join(tmpDir, "root.pem")
		leafCertPath := filepath.Join(tmpDir, "leaf.pem")

		err = os.WriteFile(rootTmplPath, []byte(rootContent), 0600)
		require.NoError(t, err)

		err = os.WriteFile(leafTmplPath, []byte(leafContent), 0600)
		require.NoError(t, err)

		err = CreateCertificates(km, config,
			rootTmplPath, leafTmplPath,
			rootCertPath, leafCertPath,
			"", "", "")
		require.NoError(t, err)

		// Verify certificates were created
		_, err = os.Stat(rootCertPath)
		require.NoError(t, err)
		_, err = os.Stat(leafCertPath)
		require.NoError(t, err)
	})

	t.Run("TSA with intermediate", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "cert-test-tsa-*")
		require.NoError(t, err)
		t.Cleanup(func() { os.RemoveAll(tmpDir) })

		intermediateContent := `{
			"subject": {
				"country": ["US"],
				"organization": ["Sigstore"],
				"organizationalUnit": ["TSA Intermediate CA"],
				"commonName": "https://tsa.com"
			},
			"issuer": {
				"commonName": "https://tsa.com"
			},
			"notBefore": "2024-01-01T00:00:00Z",
			"notAfter": "2034-01-01T00:00:00Z",
			"basicConstraints": {
				"isCA": true,
				"maxPathLen": 0
			},
			"keyUsage": [
				"certSign",
				"crlSign"
			]
		}`

		km := newMockKMSProvider()
		config := KMSConfig{
			Type:              "mockkms",
			RootKeyID:         "root-key",
			IntermediateKeyID: "intermediate-key",
			LeafKeyID:         "leaf-key",
			Options:           make(map[string]string),
		}

		rootTmplPath := filepath.Join(tmpDir, "root-template.json")
		leafTmplPath := filepath.Join(tmpDir, "leaf-template.json")
		intermediateTmplPath := filepath.Join(tmpDir, "intermediate-template.json")
		rootCertPath := filepath.Join(tmpDir, "root.pem")
		intermediateCertPath := filepath.Join(tmpDir, "intermediate.pem")
		leafCertPath := filepath.Join(tmpDir, "leaf.pem")

		err = os.WriteFile(rootTmplPath, []byte(rootContent), 0600)
		require.NoError(t, err)
		err = os.WriteFile(intermediateTmplPath, []byte(intermediateContent), 0600)
		require.NoError(t, err)
		err = os.WriteFile(leafTmplPath, []byte(leafContent), 0600)
		require.NoError(t, err)

		err = CreateCertificates(km, config,
			rootTmplPath, leafTmplPath,
			rootCertPath, leafCertPath,
			"intermediate-key", intermediateTmplPath, intermediateCertPath)
		require.NoError(t, err)

		// Verify certificates were created
		_, err = os.Stat(rootCertPath)
		require.NoError(t, err)
		_, err = os.Stat(intermediateCertPath)
		require.NoError(t, err)
		_, err = os.Stat(leafCertPath)
		require.NoError(t, err)
	})

	t.Run("invalid root template path", func(t *testing.T) {
		km := newMockKMSProvider()
		config := KMSConfig{
			Type:      "mockkms",
			RootKeyID: "root-key",
			LeafKeyID: "leaf-key",
			Options:   make(map[string]string),
		}

		err := CreateCertificates(km, config,
			"/nonexistent/root.json", "/nonexistent/leaf.json",
			"/nonexistent/root.pem", "/nonexistent/leaf.pem",
			"", "", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "error reading template file")
	})

	t.Run("invalid intermediate template path", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "cert-test-tsa-*")
		require.NoError(t, err)
		t.Cleanup(func() { os.RemoveAll(tmpDir) })

		km := newMockKMSProvider()
		config := KMSConfig{
			Type:              "mockkms",
			RootKeyID:         "root-key",
			IntermediateKeyID: "intermediate-key",
			LeafKeyID:         "leaf-key",
			Options:           make(map[string]string),
		}

		rootTmplPath := filepath.Join(tmpDir, "root-template.json")
		leafTmplPath := filepath.Join(tmpDir, "leaf-template.json")
		rootCertPath := filepath.Join(tmpDir, "root.pem")
		leafCertPath := filepath.Join(tmpDir, "leaf.pem")

		err = os.WriteFile(rootTmplPath, []byte(rootContent), 0600)
		require.NoError(t, err)
		err = os.WriteFile(leafTmplPath, []byte(leafContent), 0600)
		require.NoError(t, err)

		err = CreateCertificates(km, config,
			rootTmplPath, leafTmplPath,
			rootCertPath, leafCertPath,
			"intermediate-key", "/nonexistent/intermediate.json", "/nonexistent/intermediate.pem")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "error reading template file")
	})

	t.Run("invalid leaf template path", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "cert-test-tsa-*")
		require.NoError(t, err)
		t.Cleanup(func() { os.RemoveAll(tmpDir) })

		km := newMockKMSProvider()
		config := KMSConfig{
			Type:      "mockkms",
			RootKeyID: "root-key",
			LeafKeyID: "leaf-key",
			Options:   make(map[string]string),
		}

		rootTmplPath := filepath.Join(tmpDir, "root-template.json")
		rootCertPath := filepath.Join(tmpDir, "root.pem")
		leafCertPath := filepath.Join(tmpDir, "leaf.pem")

		err = os.WriteFile(rootTmplPath, []byte(rootContent), 0600)
		require.NoError(t, err)

		err = CreateCertificates(km, config,
			rootTmplPath, "/nonexistent/leaf.json",
			rootCertPath, leafCertPath,
			"", "", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "error reading template file")
	})
}

func TestInitKMS(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name      string
		config    KMSConfig
		wantError string
	}{
		{
			name: "AWS KMS",
			config: KMSConfig{
				Type:      "awskms",
				Region:    "us-west-2",
				RootKeyID: "test-key",
				Options: map[string]string{
					"access-key-id":     "test-access-key",
					"secret-access-key": "test-secret-key",
				},
			},
		},
		{
			name: "GCP KMS",
			config: KMSConfig{
				Type:      "gcpkms",
				RootKeyID: "test-key",
				Options: map[string]string{
					"credentials-file": "/path/to/credentials.json",
				},
			},
		},
		{
			name: "Azure KMS",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "test-key",
				Options: map[string]string{
					"tenant-id":     "test-tenant",
					"client-id":     "test-client",
					"client-secret": "test-secret",
				},
			},
		},
		{
			name: "unsupported KMS type",
			config: KMSConfig{
				Type:      "unsupportedkms",
				RootKeyID: "test-key",
			},
			wantError: "unsupported KMS type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			km, err := InitKMS(ctx, tt.config)
			if tt.wantError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
				assert.Nil(t, km)
			} else {
				// Since we can't actually connect to KMS providers in tests,
				// we expect an error but not the "unsupported KMS type" error
				require.Error(t, err)
				assert.NotContains(t, err.Error(), "unsupported KMS type")
			}
		})
	}
}
