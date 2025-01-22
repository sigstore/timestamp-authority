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
	"encoding/json"
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

var (
	originalInitKMS = InitKMS
	testKey         *ecdsa.PrivateKey
)

// mockSignerVerifier implements signature.SignerVerifier for testing
type mockSignerVerifier struct {
	key              crypto.PrivateKey
	err              error
	publicKeyFunc    func() (crypto.PublicKey, error)
	signMessageFunc  func(message io.Reader) ([]byte, error)
	cryptoSignerFunc func(context.Context, func(error)) (crypto.Signer, crypto.SignerOpts, error)
	signFunc         func(rand io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error)
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

	msgBytes, err := io.ReadAll(message)
	if err != nil {
		return nil, fmt.Errorf("error reading message: %w", err)
	}

	h := crypto.SHA256.New()
	h.Write(msgBytes)
	digest := h.Sum(nil)

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

func (m *mockSignerVerifier) CryptoSigner(_ context.Context, _ func(error)) (crypto.Signer, crypto.SignerOpts, error) {
	if m.cryptoSignerFunc != nil {
		return m.cryptoSignerFunc(context.Background(), func(err error) {
			m.err = err
		})
	}
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
			signFunc: func(rand io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
				return ecdsa.SignASN1(rand, testKey, digest)
			},
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
				RootKeyID:         "transit/keys/test-key",
				IntermediateKeyID: "transit/keys/test-intermediate-key",
				LeafKeyID:         "transit/keys/test-leaf-key",
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
	tmpDir, err := os.MkdirTemp("", "cert-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	rootTmplPath := filepath.Join(tmpDir, "root-template.json")
	rootCertPath := filepath.Join(tmpDir, "root.crt")
	leafTmplPath := filepath.Join(tmpDir, "leaf-template.json")
	leafCertPath := filepath.Join(tmpDir, "leaf.crt")

	rootTemplate := `{
		"subject": {
			"commonName": "Test Root CA"
		},
		"issuer": {
			"commonName": "Test Root CA"
		},
		"certLife": "8760h",
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 1
		}
	}`

	leafTemplate := `{
		"subject": {
			"commonName": "Test Leaf"
		},
		"issuer": {
			"commonName": "Test CA"
		},
		"certLife": "8760h",
		"keyUsage": ["digitalSignature"],
		"extKeyUsage": ["TimeStamping"],
		"basicConstraints": {
			"isCA": false
		}
	}`

	err = os.WriteFile(rootTmplPath, []byte(rootTemplate), 0644)
	require.NoError(t, err)

	err = os.WriteFile(leafTmplPath, []byte(leafTemplate), 0644)
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockSigner := &mockSignerVerifier{
		key: key,
		publicKeyFunc: func() (crypto.PublicKey, error) {
			return &key.PublicKey, nil
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
		signFunc: func(rand io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
			return ecdsa.SignASN1(rand, key, digest)
		},
	}

	config := KMSConfig{
		Type:      "awskms",
		RootKeyID: "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
		LeafKeyID: "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
		Options:   map[string]string{"aws-region": "us-west-2"},
	}

	tests := []struct {
		name      string
		rootTmpl  string
		leafTmpl  string
		rootPath  string
		leafPath  string
		signer    signature.SignerVerifier
		config    KMSConfig
		wantError string
	}{
		{
			name:     "successful_certificate_creation",
			rootTmpl: rootTmplPath,
			leafTmpl: leafTmplPath,
			rootPath: rootCertPath,
			leafPath: leafCertPath,
			signer:   mockSigner,
			config:   config,
		},
		{
			name:      "invalid_template_path",
			rootTmpl:  "nonexistent.json",
			leafTmpl:  leafTmplPath,
			rootPath:  rootCertPath,
			leafPath:  leafCertPath,
			signer:    mockSigner,
			config:    config,
			wantError: "error parsing root template: error reading template file",
		},
		{
			name:     "invalid_root_template_content",
			rootTmpl: rootTmplPath,
			leafTmpl: leafTmplPath,
			rootPath: rootCertPath,
			leafPath: leafCertPath,
			signer: &mockSignerVerifier{
				key: key,
				publicKeyFunc: func() (crypto.PublicKey, error) {
					return nil, fmt.Errorf("unsupported key type")
				},
			},
			config:    config,
			wantError: "error getting root public key: unsupported key type",
		},
		{
			name:     "signer_error",
			rootTmpl: rootTmplPath,
			leafTmpl: leafTmplPath,
			rootPath: rootCertPath,
			leafPath: leafCertPath,
			signer: &mockSignerVerifier{
				key: key,
				publicKeyFunc: func() (crypto.PublicKey, error) {
					return nil, fmt.Errorf("error getting root public key")
				},
			},
			config:    config,
			wantError: "error getting root public key",
		},
		{
			name:     "invalid_leaf_template",
			rootTmpl: rootTmplPath,
			leafTmpl: leafTmplPath,
			rootPath: rootCertPath,
			leafPath: leafCertPath,
			signer:   mockSigner,
			config: KMSConfig{
				Type:      "awskms",
				RootKeyID: "alias/test-root-key",
				LeafKeyID: "invalid-key",
				Options:   map[string]string{"aws-region": "us-west-2", "mock-leaf-error": "true"},
			},
			wantError: "leaf signing error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CreateCertificates(tt.signer, tt.config, tt.rootTmpl, tt.leafTmpl, tt.rootPath, tt.leafPath, "", "", "")
			if tt.wantError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCreateCertificatesWithoutIntermediate(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cert-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	rootTmplPath := filepath.Join(tmpDir, "root-template.json")
	rootCertPath := filepath.Join(tmpDir, "root.crt")
	leafTmplPath := filepath.Join(tmpDir, "leaf-template.json")
	leafCertPath := filepath.Join(tmpDir, "leaf.crt")

	rootTemplate := `{
		"subject": {
			"commonName": "Test Root CA"
		},
		"issuer": {
			"commonName": "Test Root CA"
		},
		"certLife": "8760h",
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 1
		}
	}`

	leafTemplate := `{
		"subject": {
			"commonName": "Test Leaf"
		},
		"issuer": {
			"commonName": "Test CA"
		},
		"certLife": "8760h",
		"keyUsage": ["digitalSignature"],
		"extKeyUsage": ["TimeStamping"],
		"basicConstraints": {
			"isCA": false
		}
	}`

	err = os.WriteFile(rootTmplPath, []byte(rootTemplate), 0644)
	require.NoError(t, err)

	err = os.WriteFile(leafTmplPath, []byte(leafTemplate), 0644)
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockSigner := &mockSignerVerifier{
		key: key,
		publicKeyFunc: func() (crypto.PublicKey, error) {
			return &key.PublicKey, nil
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
		signFunc: func(rand io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
			return ecdsa.SignASN1(rand, key, digest)
		},
	}

	config := KMSConfig{
		Type:      "awskms",
		RootKeyID: "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
		LeafKeyID: "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
		Options:   map[string]string{"aws-region": "us-west-2"},
	}

	err = CreateCertificates(mockSigner, config, rootTmplPath, leafTmplPath, rootCertPath, leafCertPath, "", "", "")
	require.NoError(t, err)
}

func TestCreateCertificatesLeafErrors(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cert-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	rootTmplPath := filepath.Join(tmpDir, "root-template.json")
	rootCertPath := filepath.Join(tmpDir, "root.crt")
	leafTmplPath := filepath.Join(tmpDir, "leaf-template.json")
	leafCertPath := filepath.Join(tmpDir, "leaf.crt")

	rootTemplate := `{
		"subject": {
			"commonName": "Test Root CA"
		},
		"issuer": {
			"commonName": "Test Root CA"
		},
		"certLife": "8760h",
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 1
		}
	}`

	leafTemplate := `invalid json`

	err = os.WriteFile(rootTmplPath, []byte(rootTemplate), 0644)
	require.NoError(t, err)

	err = os.WriteFile(leafTmplPath, []byte(leafTemplate), 0644)
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockSigner := &mockSignerVerifier{
		key: key,
		publicKeyFunc: func() (crypto.PublicKey, error) {
			return &key.PublicKey, nil
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
		signFunc: func(rand io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
			return ecdsa.SignASN1(rand, key, digest)
		},
	}

	config := KMSConfig{
		Type:      "awskms",
		RootKeyID: "alias/test-root-key",
		LeafKeyID: "alias/test-leaf-key",
		Options:   map[string]string{"aws-region": "us-west-2"},
	}

	err = CreateCertificates(mockSigner, config, rootTmplPath, leafTmplPath, rootCertPath, leafCertPath, "", "", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "error parsing leaf template: leaf template error: invalid JSON after template execution: invalid character 'i' looking for beginning of value")
}

func TestCreateCertificatesWithErrors(t *testing.T) {
	tests := []struct {
		name      string
		rootTmpl  string
		leafTmpl  string
		signer    signature.SignerVerifier
		config    KMSConfig
		wantError string
	}{
		{
			name: "root_cert_creation_error",
			rootTmpl: `{
				"subject": {
					"commonName": "Test Root CA"
				},
				"issuer": {
					"commonName": "Test Root CA"
				},
				"certLife": "invalid",
				"keyUsage": ["certSign", "crlSign"],
				"basicConstraints": {
					"isCA": true,
					"maxPathLen": 1
				}
			}`,
			leafTmpl: `{
				"subject": {
					"commonName": "Test TSA"
				},
				"issuer": {
					"commonName": "Test Root CA"
				},
				"certLife": "8760h",
				"keyUsage": ["digitalSignature"],
				"extensions": [
					{
						"id": "2.5.29.37",
						"critical": true,
						"value": "MCQwIgYDVR0lBBswGQYIKwYBBQUHAwgGDSsGAQQBgjcUAgICAf8="
					}
				]
			}`,
			signer: &mockSignerVerifier{},
			config: KMSConfig{
				Type:      "awskms",
				RootKeyID: "alias/test-root-key",
				LeafKeyID: "alias/test-leaf-key",
			},
			wantError: "error parsing root template: template validation error: invalid certLife format: time: invalid duration \"invalid\"",
		},
		{
			name: "root_cert_sign_error",
			rootTmpl: `{
				"subject": {
					"commonName": "Test Root CA"
				},
				"issuer": {
					"commonName": "Test Root CA"
				},
				"certLife": "8760h",
				"keyUsage": ["certSign", "crlSign"],
				"basicConstraints": {
					"isCA": true,
					"maxPathLen": 1
				}
			}`,
			leafTmpl: `{
				"subject": {
					"commonName": "Test TSA"
				},
				"issuer": {
					"commonName": "Test Root CA"
				},
				"certLife": "8760h",
				"keyUsage": ["digitalSignature"],
				"extKeyUsage": ["TimeStamping"],
				"basicConstraints": {
					"isCA": false
				}
			}`,
			signer: &mockSignerVerifier{
				publicKeyFunc: func() (crypto.PublicKey, error) {
					return nil, fmt.Errorf("signing error")
				},
			},
			config: KMSConfig{
				Type:      "awskms",
				RootKeyID: "alias/test-root-key",
				LeafKeyID: "alias/test-leaf-key",
				Options:   map[string]string{"aws-region": "us-west-2"},
			},
			wantError: "error getting root public key: signing error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, err := os.MkdirTemp("", "cert-test-*")
			require.NoError(t, err)

			rootTmplPath := filepath.Join(tmpDir, "root-template.json")
			rootCertPath := filepath.Join(tmpDir, "root.crt")
			leafTmplPath := filepath.Join(tmpDir, "leaf-template.json")
			leafCertPath := filepath.Join(tmpDir, "leaf.crt")

			err = os.WriteFile(rootTmplPath, []byte(tt.rootTmpl), 0644)
			require.NoError(t, err)

			err = os.WriteFile(leafTmplPath, []byte(tt.leafTmpl), 0644)
			require.NoError(t, err)

			err = CreateCertificates(tt.signer, tt.config, rootTmplPath, leafTmplPath, rootCertPath, leafCertPath, "", "", "")
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantError)
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

	rootTmplPath := filepath.Join(tmpDir, "root-template.json")
	rootCertPath := filepath.Join(tmpDir, "root.crt")
	leafTmplPath := filepath.Join(tmpDir, "leaf-template.json")
	leafCertPath := filepath.Join(tmpDir, "leaf.crt")

	rootTemplate := `{
		"subject": {
			"commonName": "Test Root CA"
		},
		"issuer": {
			"commonName": "Test Root CA"
		},
		"certLife": "8760h",
		"keyUsage": ["digitalSignature"],
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 1
		}
	}`

	leafTemplate := `{
		"subject": {
			"commonName": "Test TSA"
		},
		"issuer": {
			"commonName": "Test Root CA"
		},
		"certLife": "8760h",
		"keyUsage": ["digitalSignature"],
		"extKeyUsage": ["serverAuth"],
		"basicConstraints": {
			"isCA": false
		}
	}`

	err = os.WriteFile(rootTmplPath, []byte(rootTemplate), 0644)
	require.NoError(t, err)

	err = os.WriteFile(leafTmplPath, []byte(leafTemplate), 0644)
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockSigner := &mockSignerVerifier{
		key: key,
		publicKeyFunc: func() (crypto.PublicKey, error) {
			return &key.PublicKey, nil
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
		signFunc: func(rand io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
			return ecdsa.SignASN1(rand, key, digest)
		},
	}

	config := KMSConfig{
		Type:      "awskms",
		RootKeyID: "alias/test-root-key",
		LeafKeyID: "alias/test-leaf-key",
	}

	err = CreateCertificates(mockSigner, config, rootTmplPath, leafTmplPath, rootCertPath, leafCertPath, "", "", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "CA certificate must have certSign key usage")
}

func TestCreateCertificatesWithInvalidIntermediateKey(t *testing.T) {
	defer func() { InitKMS = originalInitKMS }()

	InitKMS = func(_ context.Context, config KMSConfig) (signature.SignerVerifier, error) {
		if config.IntermediateKeyID != "" && !strings.HasPrefix(config.IntermediateKeyID, "arn:aws:kms:") && !strings.HasPrefix(config.IntermediateKeyID, "alias/") {
			return nil, fmt.Errorf("invalid KMS configuration: awskms RootKeyID must start with 'arn:aws:kms:' or 'alias/'")
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return &mockSignerVerifier{
			key: key,
			signFunc: func(rand io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
				return ecdsa.SignASN1(rand, key, digest)
			},
		}, nil
	}

	tmpDir, err := os.MkdirTemp("", "cert-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	rootTmplPath := filepath.Join(tmpDir, "root-template.json")
	rootCertPath := filepath.Join(tmpDir, "root.crt")
	leafTmplPath := filepath.Join(tmpDir, "leaf-template.json")
	leafCertPath := filepath.Join(tmpDir, "leaf.crt")
	intermediateTmplPath := filepath.Join(tmpDir, "intermediate-template.json")
	intermediateCertPath := filepath.Join(tmpDir, "intermediate.crt")

	rootTemplate := `{
		"subject": {
			"commonName": "Test Root CA"
		},
		"issuer": {
			"commonName": "Test Root CA"
		},
		"certLife": "8760h",
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 1
		}
	}`

	intermediateTemplate := `{
		"subject": {
			"commonName": "Test Intermediate CA"
		},
		"issuer": {
			"commonName": "Test Root CA"
		},
		"certLife": "8760h",
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 0
		}
	}`

	leafTemplate := `{
		"subject": {
			"commonName": "Test TSA"
		},
		"issuer": {
			"commonName": "Test Intermediate CA"
		},
		"certLife": "8760h",
		"keyUsage": ["digitalSignature"],
		"extKeyUsage": ["TimeStamping"],
		"basicConstraints": {
			"isCA": false
		}
	}`

	err = os.WriteFile(rootTmplPath, []byte(rootTemplate), 0644)
	require.NoError(t, err)

	err = os.WriteFile(intermediateTmplPath, []byte(intermediateTemplate), 0644)
	require.NoError(t, err)

	err = os.WriteFile(leafTmplPath, []byte(leafTemplate), 0644)
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockSigner := &mockSignerVerifier{
		key: key,
		publicKeyFunc: func() (crypto.PublicKey, error) {
			return &key.PublicKey, nil
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
		signFunc: func(rand io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
			return ecdsa.SignASN1(rand, key, digest)
		},
	}

	config := KMSConfig{
		Type:              "awskms",
		RootKeyID:         "alias/test-root-key",
		IntermediateKeyID: "invalid-key",
		LeafKeyID:         "alias/test-leaf-key",
		Options:           map[string]string{"aws-region": "us-west-2"},
	}

	err = CreateCertificates(mockSigner, config, rootTmplPath, leafTmplPath, rootCertPath, leafCertPath, config.IntermediateKeyID, intermediateTmplPath, intermediateCertPath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid KMS configuration: awskms RootKeyID must start with 'arn:aws:kms:' or 'alias/'")
}

func TestCreateCertificatesWithInvalidLeafKey(t *testing.T) {
	oldInitKMS := InitKMS
	defer func() { InitKMS = oldInitKMS }()

	InitKMS = func(_ context.Context, config KMSConfig) (signature.SignerVerifier, error) {
		if config.LeafKeyID == "invalid-key" {
			return nil, fmt.Errorf("invalid KMS configuration: awskms RootKeyID must start with 'arn:aws:kms:' or 'alias/'")
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return &mockSignerVerifier{
			key: key,
			signFunc: func(rand io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
				return ecdsa.SignASN1(rand, key, digest)
			},
		}, nil
	}

	tmpDir, err := os.MkdirTemp("", "cert-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	rootTmplPath := filepath.Join(tmpDir, "root-template.json")
	rootCertPath := filepath.Join(tmpDir, "root.crt")
	leafTmplPath := filepath.Join(tmpDir, "leaf-template.json")
	leafCertPath := filepath.Join(tmpDir, "leaf.crt")

	rootTemplate := `{
		"subject": {
			"commonName": "Test Root CA"
		},
		"issuer": {
			"commonName": "Test Root CA"
		},
		"certLife": "8760h",
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 1
		}
	}`

	leafTemplate := `{
		"subject": {
			"commonName": "Test TSA"
		},
		"issuer": {
			"commonName": "Test Root CA"
		},
		"certLife": "8760h",
		"keyUsage": ["digitalSignature"],
		"extKeyUsage": ["TimeStamping"],
		"basicConstraints": {
			"isCA": false
		}
	}`

	err = os.WriteFile(rootTmplPath, []byte(rootTemplate), 0644)
	require.NoError(t, err)

	err = os.WriteFile(leafTmplPath, []byte(leafTemplate), 0644)
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockSigner := &mockSignerVerifier{
		key: key,
		publicKeyFunc: func() (crypto.PublicKey, error) {
			return &key.PublicKey, nil
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
		signFunc: func(rand io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
			return ecdsa.SignASN1(rand, key, digest)
		},
	}

	config := KMSConfig{
		Type:      "awskms",
		RootKeyID: "alias/test-root-key",
		LeafKeyID: "invalid-key",
		Options:   map[string]string{"aws-region": "us-west-2"},
	}

	err = CreateCertificates(mockSigner, config, rootTmplPath, leafTmplPath, rootCertPath, leafCertPath, "", "", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid KMS configuration: awskms RootKeyID must start with 'arn:aws:kms:' or 'alias/'")
}

func TestCreateCertificatesWithInvalidRootKey(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T) (string, string, string, string, KMSConfig, signature.SignerVerifier)
		wantError string
	}{
		{
			name: "signing_error",
			setup: func(t *testing.T) (string, string, string, string, KMSConfig, signature.SignerVerifier) {
				tmpDir, err := os.MkdirTemp("", "cert-test-*")
				require.NoError(t, err)

				rootTmplPath := filepath.Join(tmpDir, "root-template.json")
				rootCertPath := filepath.Join(tmpDir, "root.crt")
				leafTmplPath := filepath.Join(tmpDir, "leaf-template.json")
				leafCertPath := filepath.Join(tmpDir, "leaf.crt")

				rootTemplate := `{
					"subject": {
						"commonName": "Test Root CA"
					},
					"issuer": {
						"commonName": "Test Root CA"
					},
					"certLife": "8760h",
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {
						"isCA": true,
						"maxPathLen": 1
					}
				}`

				leafTemplate := `{
					"subject": {
						"commonName": "Test TSA"
					},
					"issuer": {
						"commonName": "Test Root CA"
					},
					"certLife": "8760h",
					"keyUsage": ["digitalSignature"],
					"extKeyUsage": ["TimeStamping"],
					"basicConstraints": {
						"isCA": false
					}
				}`

				err = os.WriteFile(rootTmplPath, []byte(rootTemplate), 0644)
				require.NoError(t, err)

				err = os.WriteFile(leafTmplPath, []byte(leafTemplate), 0644)
				require.NoError(t, err)

				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)

				mockSigner := &mockSignerVerifier{
					key: key,
					publicKeyFunc: func() (crypto.PublicKey, error) {
						return nil, fmt.Errorf("signing error")
					},
					signMessageFunc: func(_ io.Reader) ([]byte, error) {
						return nil, fmt.Errorf("signing error")
					},
					signFunc: func(rand io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
						return ecdsa.SignASN1(rand, key, digest)
					},
				}

				config := KMSConfig{
					Type:      "awskms",
					RootKeyID: "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
					LeafKeyID: "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
					Options:   map[string]string{"aws-region": "us-west-2"},
				}

				return rootTmplPath, rootCertPath, leafTmplPath, leafCertPath, config, mockSigner
			},
			wantError: "error getting root public key: signing error",
		},
		{
			name: "invalid_root_key",
			setup: func(t *testing.T) (string, string, string, string, KMSConfig, signature.SignerVerifier) {
				tmpDir := t.TempDir()

				rootTmplPath := filepath.Join(tmpDir, "root-template.json")
				rootCertPath := filepath.Join(tmpDir, "root.crt")
				leafTmplPath := filepath.Join(tmpDir, "leaf-template.json")
				leafCertPath := filepath.Join(tmpDir, "leaf.crt")

				rootTemplate := `{
					"subject": {
						"commonName": "Test Root CA"
					},
					"issuer": {
						"commonName": "Test Root CA"
					},
					"certLife": "8760h",
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {
						"isCA": true,
						"maxPathLen": 1
					}
				}`

				leafTemplate := `{
					"subject": {
						"commonName": "Test TSA"
					},
					"issuer": {
						"commonName": "Test Root CA"
					},
					"certLife": "8760h",
					"keyUsage": ["digitalSignature"],
					"extKeyUsage": ["TimeStamping"],
					"basicConstraints": {
						"isCA": false
					}
				}`

				err := os.WriteFile(rootTmplPath, []byte(rootTemplate), 0644)
				require.NoError(t, err)
				err = os.WriteFile(leafTmplPath, []byte(leafTemplate), 0644)
				require.NoError(t, err)

				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)

				mockSigner := &mockSignerVerifier{
					key: key,
					publicKeyFunc: func() (crypto.PublicKey, error) {
						return nil, fmt.Errorf("invalid KMS configuration: awskms RootKeyID must start with 'arn:aws:kms:' or 'alias/'")
					},
					signMessageFunc: func(_ io.Reader) ([]byte, error) {
						return nil, fmt.Errorf("invalid KMS configuration: awskms RootKeyID must start with 'arn:aws:kms:' or 'alias/'")
					},
					signFunc: func(rand io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
						return ecdsa.SignASN1(rand, key, digest)
					},
				}

				config := KMSConfig{
					Type:      "awskms",
					RootKeyID: "invalid-key",
					LeafKeyID: "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
					Options:   map[string]string{"aws-region": "us-west-2"},
				}

				return rootTmplPath, rootCertPath, leafTmplPath, leafCertPath, config, mockSigner
			},
			wantError: "error getting root public key: invalid KMS configuration: awskms RootKeyID must start with 'arn:aws:kms:' or 'alias/'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rootTmpl, rootCert, leafTmpl, leafCert, config, signer := tt.setup(t)
			err := CreateCertificates(signer, config, rootTmpl, leafTmpl, rootCert, leafCert, "", "", "")
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantError)
		})
	}
}

func TestCreateCertificatesWithInvalidLeafTemplate(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T) (string, string, string, string, KMSConfig, signature.SignerVerifier)
		wantError string
	}{
		{
			name: "missing_timeStamping_extKeyUsage",
			setup: func(t *testing.T) (string, string, string, string, KMSConfig, signature.SignerVerifier) {
				tmpDir := t.TempDir()

				rootTmplPath := filepath.Join(tmpDir, "root-template.json")
				rootCertPath := filepath.Join(tmpDir, "root.crt")
				leafTmplPath := filepath.Join(tmpDir, "leaf-template.json")
				leafCertPath := filepath.Join(tmpDir, "leaf.crt")

				rootTemplate := `{
					"subject": {
						"commonName": "Test Root CA"
					},
					"issuer": {
						"commonName": "Test Root CA"
					},
					"certLife": "8760h",
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {
						"isCA": true,
						"maxPathLen": 1
					}
				}`

				leafTemplate := `{
					"subject": {
						"commonName": "Test TSA"
					},
					"issuer": {
						"commonName": "Test Root CA"
					},
					"certLife": "8760h",
					"keyUsage": ["digitalSignature"],
					"basicConstraints": {
						"isCA": false
					}
				}`

				err := os.WriteFile(rootTmplPath, []byte(rootTemplate), 0644)
				require.NoError(t, err)
				err = os.WriteFile(leafTmplPath, []byte(leafTemplate), 0644)
				require.NoError(t, err)

				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)

				mockSigner := &mockSignerVerifier{
					key: key,
					publicKeyFunc: func() (crypto.PublicKey, error) {
						return &key.PublicKey, nil
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
					signFunc: func(rand io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
						return ecdsa.SignASN1(rand, key, digest)
					},
				}

				config := KMSConfig{
					Type:      "awskms",
					RootKeyID: "alias/test-root-key",
					LeafKeyID: "invalid-key",
					Options:   map[string]string{"aws-region": "us-west-2"},
				}

				return rootTmplPath, rootCertPath, leafTmplPath, leafCertPath, config, mockSigner
			},
			wantError: "error parsing leaf template: template validation error: timestamp authority certificate must have TimeStamping extended key usage",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rootTmpl, rootCert, leafTmpl, leafCert, config, signer := tt.setup(t)
			err := CreateCertificates(signer, config, rootTmpl, leafTmpl, rootCert, leafCert, "", "", "")
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
					"certLife": "8760h"
				}`), 0600)
				require.NoError(t, err)

				leafTemplate := filepath.Join(tmpDir, "leaf.json")
				err = os.WriteFile(leafTemplate, []byte(`{invalid json`), 0600)
				require.NoError(t, err)

				intermediateTemplate := filepath.Join(tmpDir, "intermediate.json")
				err = os.WriteFile(intermediateTemplate, []byte(`{invalid json`), 0600)
				require.NoError(t, err)

				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)

				mockSigner := &mockSignerVerifier{
					key: key,
					publicKeyFunc: func() (crypto.PublicKey, error) {
						return &key.PublicKey, nil
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
					signFunc: func(rand io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
						return ecdsa.SignASN1(rand, key, digest)
					},
				}

				return tmpDir, KMSConfig{
					Type:              "awskms",
					RootKeyID:         "alias/test-root-key",
					IntermediateKeyID: "alias/test-leaf-key",
					LeafKeyID:         "alias/test-leaf-key",
					Options:           map[string]string{"aws-region": "us-west-2"},
				}, mockSigner
			},
			wantError: "error parsing intermediate template: leaf template error: invalid JSON after template execution: invalid character 'i' looking for beginning of object key string",
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
					"certLife": "8760h"
				}`), 0600)
				require.NoError(t, err)

				leafTemplate := filepath.Join(tmpDir, "leaf.json")
				err = os.WriteFile(leafTemplate, []byte(`{
					"subject": {"commonName": "Test Leaf"},
					"keyUsage": ["digitalSignature"],
					"extKeyUsage": ["TimeStamping"],
					"basicConstraints": {"isCA": false},
					"certLife": "8760h"
				}`), 0600)
				require.NoError(t, err)

				intermediateTemplate := filepath.Join(tmpDir, "intermediate.json")
				err = os.WriteFile(intermediateTemplate, []byte(`{
					"subject": {"commonName": "Test Intermediate CA"},
					"keyUsage": ["digitalSignature"],
					"basicConstraints": {"isCA": true, "maxPathLen": 0},
					"certLife": "43800h"
				}`), 0600)
				require.NoError(t, err)

				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)

				mockSigner := &mockSignerVerifier{
					key: key,
					publicKeyFunc: func() (crypto.PublicKey, error) {
						return &key.PublicKey, nil
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
					signFunc: func(rand io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
						return ecdsa.SignASN1(rand, key, digest)
					},
				}

				return tmpDir, KMSConfig{
					Type:              "awskms",
					RootKeyID:         "alias/test-root-key",
					IntermediateKeyID: "alias/test-leaf-key",
					LeafKeyID:         "alias/test-leaf-key",
					Options:           map[string]string{"aws-region": "us-west-2"},
				}, mockSigner
			},
			wantError: "error parsing intermediate template: template validation error: CA certificate must have certSign key usage",
		},
		{
			name: "invalid_intermediate_lifetime",
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
					"certLife": "8760h"
				}`), 0600)
				require.NoError(t, err)

				leafTemplate := filepath.Join(tmpDir, "leaf.json")
				err = os.WriteFile(leafTemplate, []byte(`{
					"subject": {"commonName": "Test Leaf"},
					"keyUsage": ["digitalSignature"],
					"extKeyUsage": ["TimeStamping"],
					"basicConstraints": {"isCA": false},
					"certLife": "8760h"
				}`), 0600)
				require.NoError(t, err)

				intermediateTemplate := filepath.Join(tmpDir, "intermediate.json")
				err = os.WriteFile(intermediateTemplate, []byte(`{
					"subject": {"commonName": "Test Intermediate CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 0},
					"certLife": "invalid-time"
				}`), 0600)
				require.NoError(t, err)

				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)

				mockSigner := &mockSignerVerifier{
					key: key,
					publicKeyFunc: func() (crypto.PublicKey, error) {
						return &key.PublicKey, nil
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
					signFunc: func(rand io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
						return ecdsa.SignASN1(rand, key, digest)
					},
				}

				return tmpDir, KMSConfig{
					Type:              "awskms",
					RootKeyID:         "alias/test-root-key",
					IntermediateKeyID: "alias/test-leaf-key",
					LeafKeyID:         "alias/test-leaf-key",
					Options:           map[string]string{"aws-region": "us-west-2"},
				}, mockSigner
			},
			wantError: "error parsing intermediate template: template validation error: invalid certLife format: time: invalid duration \"invalid-time\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, config, signer := tt.setup(t)
			defer os.RemoveAll(tmpDir)

			err := CreateCertificates(signer, config,
				filepath.Join(tmpDir, "root.json"),
				filepath.Join(tmpDir, "leaf.json"),
				filepath.Join(tmpDir, "out", "root.crt"),
				filepath.Join(tmpDir, "out", "leaf.crt"),
				config.IntermediateKeyID,
				filepath.Join(tmpDir, "intermediate.json"),
				filepath.Join(tmpDir, "out", "intermediate.crt"))

			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantError)
		})
	}
}

func TestValidateKMSConfig_AdditionalCases(t *testing.T) {
	tests := []struct {
		name    string
		config  KMSConfig
		wantErr string
	}{
		{
			name: "invalid_aws_kms_key_format",
			config: KMSConfig{
				Type:      "awskms",
				RootKeyID: "invalid-format",
				LeafKeyID: "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
				Options:   map[string]string{"aws-region": "us-west-2"},
			},
			wantErr: "awskms RootKeyID must start with 'arn:aws:kms:' or 'alias/'",
		},
		{
			name: "invalid_gcp_kms_key_format",
			config: KMSConfig{
				Type:      "gcpkms",
				RootKeyID: "invalid-format",
				LeafKeyID: "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1",
			},
			wantErr: "gcpkms RootKeyID must start with 'projects/'",
		},
		{
			name: "invalid_azure_kms_key_format",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "invalid-format",
				LeafKeyID: "azurekms:name=test-key;vault=test-vault",
				Options:   map[string]string{"azure-tenant-id": "test-tenant"},
			},
			wantErr: "azurekms RootKeyID must start with 'azurekms:name='",
		},
		{
			name: "missing_azure_tenant_id",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "azurekms:name=test-key;vault=test-vault",
				LeafKeyID: "azurekms:name=test-key;vault=test-vault",
			},
			wantErr: "options map is required for Azure KMS",
		},
		{
			name: "missing_hashivault_options",
			config: KMSConfig{
				Type:      "hashivault",
				RootKeyID: "test-key",
				LeafKeyID: "test-key",
			},
			wantErr: "options map is required for HashiVault KMS",
		},
		{
			name: "missing_hashivault_token",
			config: KMSConfig{
				Type:      "hashivault",
				RootKeyID: "test-key",
				LeafKeyID: "test-key",
				Options:   map[string]string{"vault-address": "http://localhost:8200"},
			},
			wantErr: "vault-token is required for HashiVault KMS",
		},
		{
			name: "missing_hashivault_address",
			config: KMSConfig{
				Type:      "hashivault",
				RootKeyID: "test-key",
				LeafKeyID: "test-key",
				Options:   map[string]string{"vault-token": "test-token"},
			},
			wantErr: "vault-address is required for HashiVault KMS",
		},
		{
			name: "invalid_gcp_intermediate_key",
			config: KMSConfig{
				Type:              "gcpkms",
				RootKeyID:         "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1",
				IntermediateKeyID: "invalid-format",
				LeafKeyID:         "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1",
			},
			wantErr: "gcpkms IntermediateKeyID must start with 'projects/'",
		},
		{
			name: "invalid_azure_leaf_key",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "azurekms:name=test-key;vault=test-vault",
				LeafKeyID: "invalid-format",
				Options:   map[string]string{"azure-tenant-id": "test-tenant"},
			},
			wantErr: "azurekms LeafKeyID must start with 'azurekms:name='",
		},
		{
			name: "unsupported_kms_type",
			config: KMSConfig{
				Type:      "unsupported",
				RootKeyID: "test-key",
				LeafKeyID: "test-key",
			},
			wantErr: "unsupported KMS type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKMSConfig(tt.config)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestCreateCertificates_CryptoSignerErrors(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cert-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	rootTmplPath := filepath.Join(tmpDir, "root-template.json")
	rootCertPath := filepath.Join(tmpDir, "root.crt")
	leafTmplPath := filepath.Join(tmpDir, "leaf-template.json")
	leafCertPath := filepath.Join(tmpDir, "leaf.crt")

	rootTemplate := `{
		"subject": {
			"commonName": "Test Root CA"
		},
		"issuer": {
			"commonName": "Test Root CA"
		},
		"certLife": "8760h",
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 1
		}
	}`

	leafTemplate := `{
		"subject": {
			"commonName": "Test TSA"
		},
		"issuer": {
			"commonName": "Test Root CA"
		},
		"certLife": "8760h",
		"keyUsage": ["digitalSignature"],
		"extKeyUsage": ["TimeStamping"],
		"basicConstraints": {
			"isCA": false
		}
	}`

	err = os.WriteFile(rootTmplPath, []byte(rootTemplate), 0644)
	require.NoError(t, err)

	err = os.WriteFile(leafTmplPath, []byte(leafTemplate), 0644)
	require.NoError(t, err)

	t.Run("signer_not_implementing_cryptosigner", func(t *testing.T) {
		mockSigner := &mockSignerVerifier{
			publicKeyFunc: func() (crypto.PublicKey, error) {
				return nil, nil
			},
			cryptoSignerFunc: func(_ context.Context, _ func(error)) (crypto.Signer, crypto.SignerOpts, error) {
				return nil, nil, fmt.Errorf("signer does not implement CryptoSigner")
			},
		}

		config := KMSConfig{
			Type:      "awskms",
			RootKeyID: "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
			LeafKeyID: "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
			Options:   map[string]string{"aws-region": "us-west-2"},
		}

		err := CreateCertificates(mockSigner, config, rootTmplPath, leafTmplPath, rootCertPath, leafCertPath, "", "", "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "error getting root crypto signer: signer does not implement CryptoSigner")
	})

	t.Run("cryptosigner_error", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		mockSigner := &mockSignerVerifier{
			key: key,
			publicKeyFunc: func() (crypto.PublicKey, error) {
				return &key.PublicKey, nil
			},
			cryptoSignerFunc: func(_ context.Context, _ func(error)) (crypto.Signer, crypto.SignerOpts, error) {
				return nil, nil, fmt.Errorf("crypto signer error")
			},
		}

		config := KMSConfig{
			Type:      "awskms",
			RootKeyID: "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
			LeafKeyID: "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
			Options:   map[string]string{"aws-region": "us-west-2"},
		}

		certErr := CreateCertificates(mockSigner, config, rootTmplPath, leafTmplPath, rootCertPath, leafCertPath, "", "", "")
		require.Error(t, certErr)
		require.Contains(t, certErr.Error(), "error getting root crypto signer: crypto signer error")
	})
}

func TestValidateTemplate_AdditionalCases(t *testing.T) {
	tests := []struct {
		name      string
		template  string
		parent    *x509.Certificate
		wantError string
	}{
		{
			name: "missing_key_usage",
			template: `{
				"subject": {
					"commonName": "Test CA"
				},
				"issuer": {
					"commonName": "Test CA"
				},
				"certLife": "8760h",
				"basicConstraints": {
					"isCA": true,
					"maxPathLen": 1
				}
			}`,
			wantError: "CA certificate must specify at least one key usage",
		},
		{
			name: "invalid_key_usage_combination",
			template: `{
				"subject": {
					"commonName": "Test CA"
				},
				"issuer": {
					"commonName": "Test CA"
				},
				"certLife": "8760h",
				"keyUsage": ["digitalSignature", "keyEncipherment"],
				"basicConstraints": {
					"isCA": true,
					"maxPathLen": 1
				}
			}`,
			wantError: "CA certificate must have certSign key usage",
		},
		{
			name: "invalid_basic_constraints",
			template: `{
				"subject": {
					"commonName": "Test CA"
				},
				"issuer": {
					"commonName": "Test CA"
				},
				"certLife": "8760h",
				"keyUsage": ["certSign", "crlSign"],
				"basicConstraints": {
					"isCA": false,
					"maxPathLen": 1
				}
			}`,
			wantError: "CA certificate must have isCA set to true",
		},
		{
			name: "invalid_ext_key_usage_for_leaf",
			template: `{
				"subject": {
					"commonName": "Test Leaf"
				},
				"issuer": {
					"commonName": "Test CA"
				},
				"certLife": "8760h",
				"keyUsage": ["digitalSignature"],
				"extKeyUsage": ["serverAuth"],
				"basicConstraints": {
					"isCA": false
				}
			}`,
			parent: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "Test CA",
				},
			},
			wantError: "timestamp authority certificate must have TimeStamping extended key usage",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "template-*.json")
			require.NoError(t, err)
			defer os.Remove(tmpFile.Name())

			err = os.WriteFile(tmpFile.Name(), []byte(tt.template), 0644)
			require.NoError(t, err)

			var certTmpl CertificateTemplate
			err = json.Unmarshal([]byte(tt.template), &certTmpl)
			require.NoError(t, err)

			err = ValidateTemplate(&certTmpl, tt.parent)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantError)
		})
	}
}

func TestCreateCertificateFromTemplate(t *testing.T) {
	tests := []struct {
		name      string
		template  *CertificateTemplate
		parent    *x509.Certificate
		wantError string
	}{
		{
			name: "invalid_cert_lifetime_format",
			template: &CertificateTemplate{
				Subject: struct {
					Country            []string `json:"country,omitempty"`
					Organization       []string `json:"organization,omitempty"`
					OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
					CommonName         string   `json:"commonName"`
				}{
					CommonName: "Test CA",
				},
				CertLifetime: "invalid",
				KeyUsage:     []string{"certSign"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{
					IsCA:       true,
					MaxPathLen: 1,
				},
			},
			wantError: "invalid certLife format",
		},
		{
			name: "invalid_extension_oid",
			template: &CertificateTemplate{
				Subject: struct {
					Country            []string `json:"country,omitempty"`
					Organization       []string `json:"organization,omitempty"`
					OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
					CommonName         string   `json:"commonName"`
				}{
					CommonName: "Test CA",
				},
				CertLifetime: "8760h",
				KeyUsage:     []string{"certSign"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{
					IsCA:       true,
					MaxPathLen: 1,
				},
				Extensions: []struct {
					ID       string `json:"id"`
					Critical bool   `json:"critical"`
					Value    string `json:"value"`
				}{
					{
						ID:       "invalid.oid",
						Critical: true,
						Value:    "AQID",
					},
				},
			},
			wantError: "invalid OID in extension",
		},
		{
			name: "invalid_extension_value",
			template: &CertificateTemplate{
				Subject: struct {
					Country            []string `json:"country,omitempty"`
					Organization       []string `json:"organization,omitempty"`
					OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
					CommonName         string   `json:"commonName"`
				}{
					CommonName: "Test CA",
				},
				CertLifetime: "8760h",
				KeyUsage:     []string{"certSign"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{
					IsCA:       true,
					MaxPathLen: 1,
				},
				Extensions: []struct {
					ID       string `json:"id"`
					Critical bool   `json:"critical"`
					Value    string `json:"value"`
				}{
					{
						ID:       "2.5.29.37",
						Critical: true,
						Value:    "invalid-base64",
					},
				},
			},
			wantError: "error decoding extension value",
		},
		{
			name: "successful_non_ca_cert",
			template: &CertificateTemplate{
				Subject: struct {
					Country            []string `json:"country,omitempty"`
					Organization       []string `json:"organization,omitempty"`
					OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
					CommonName         string   `json:"commonName"`
				}{
					CommonName:         "Test Leaf",
					Country:            []string{"US"},
					Organization:       []string{"Test Org"},
					OrganizationalUnit: []string{"Test Unit"},
				},
				CertLifetime: "8760h",
				KeyUsage:     []string{"digitalSignature"},
				ExtKeyUsage:  []string{"TimeStamping"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{
					IsCA: false,
				},
			},
			parent: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "Test CA",
				},
			},
		},
		{
			name: "successful_ca_cert_with_extensions",
			template: &CertificateTemplate{
				Subject: struct {
					Country            []string `json:"country,omitempty"`
					Organization       []string `json:"organization,omitempty"`
					OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
					CommonName         string   `json:"commonName"`
				}{
					CommonName: "Test CA",
				},
				CertLifetime: "8760h",
				KeyUsage:     []string{"certSign", "crlSign", "digitalSignature"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{
					IsCA:       true,
					MaxPathLen: 0,
				},
				Extensions: []struct {
					ID       string `json:"id"`
					Critical bool   `json:"critical"`
					Value    string `json:"value"`
				}{
					{
						ID:       "2.5.29.37",
						Critical: true,
						Value:    "MCQwIgYDVR0lBBswGQYIKwYBBQUHAwgGDSsGAQQBgjcUAgICAf8=",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := CreateCertificateFromTemplate(tt.template, tt.parent)
			if tt.wantError != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.wantError)
			} else {
				require.NoError(t, err)
				require.NotNil(t, cert)

				if tt.parent != nil {
					require.Equal(t, tt.parent.Subject, cert.Issuer)
				} else {
					require.Equal(t, tt.template.Issuer.CommonName, cert.Issuer.CommonName)
				}

				require.Equal(t, tt.template.Subject.CommonName, cert.Subject.CommonName)
				require.Equal(t, tt.template.Subject.Country, cert.Subject.Country)
				require.Equal(t, tt.template.Subject.Organization, cert.Subject.Organization)
				require.Equal(t, tt.template.Subject.OrganizationalUnit, cert.Subject.OrganizationalUnit)
				require.Equal(t, tt.template.BasicConstraints.IsCA, cert.IsCA)

				if tt.template.BasicConstraints.IsCA {
					require.Equal(t, tt.template.BasicConstraints.MaxPathLen, cert.MaxPathLen)
					require.Equal(t, tt.template.BasicConstraints.MaxPathLen == 0, cert.MaxPathLenZero)
				}

				if len(tt.template.KeyUsage) > 0 {
					for _, usage := range tt.template.KeyUsage {
						switch usage {
						case "certSign":
							require.True(t, cert.KeyUsage&x509.KeyUsageCertSign != 0)
						case "crlSign":
							require.True(t, cert.KeyUsage&x509.KeyUsageCRLSign != 0)
						case "digitalSignature":
							require.True(t, cert.KeyUsage&x509.KeyUsageDigitalSignature != 0)
						}
					}
				}

				// Verify extended key usages for non-CA certs
				if !tt.template.BasicConstraints.IsCA && len(tt.template.ExtKeyUsage) > 0 {
					for _, usage := range tt.template.ExtKeyUsage {
						if usage == "TimeStamping" {
							require.Contains(t, cert.ExtKeyUsage, x509.ExtKeyUsageTimeStamping)
						}
					}
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
			publicKeyFunc: func() (crypto.PublicKey, error) {
				return &key.PublicKey, nil
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
			signFunc: func(rand io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
				return ecdsa.SignASN1(rand, key, digest)
			},
		}, nil
	}

	tmpDir, err := os.MkdirTemp("", "cert-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	rootTmplPath := filepath.Join(tmpDir, "root-template.json")
	leafTmplPath := filepath.Join(tmpDir, "leaf-template.json")

	rootTemplate := `{
		"subject": {
			"commonName": "Test Root CA"
		},
		"issuer": {
			"commonName": "Test Root CA"
		},
		"certLife": "8760h",
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 1
		}
	}`

	leafTemplate := `{
		"subject": {
			"commonName": "Test Leaf"
		},
		"issuer": {
			"commonName": "Test CA"
		},
		"certLife": "8760h",
		"keyUsage": ["digitalSignature"],
		"extKeyUsage": ["TimeStamping"],
		"basicConstraints": {
			"isCA": false
		}
	}`

	err = os.WriteFile(rootTmplPath, []byte(rootTemplate), 0644)
	require.NoError(t, err)

	err = os.WriteFile(leafTmplPath, []byte(leafTemplate), 0644)
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockSigner := &mockSignerVerifier{
		key: key,
		publicKeyFunc: func() (crypto.PublicKey, error) {
			return &key.PublicKey, nil
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
		signFunc: func(rand io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
			return ecdsa.SignASN1(rand, key, digest)
		},
	}

	config := KMSConfig{
		Type:      "mock",
		RootKeyID: "test-root-key",
		LeafKeyID: "test-leaf-key",
	}

	readOnlyDir := filepath.Join(tmpDir, "readonly")
	err = os.MkdirAll(readOnlyDir, 0755)
	require.NoError(t, err)
	err = os.Chmod(readOnlyDir, 0500)
	require.NoError(t, err)

	tests := []struct {
		name      string
		rootPath  string
		leafPath  string
		wantError string
	}{
		{
			name:      "root_cert_write_error",
			rootPath:  filepath.Join(readOnlyDir, "root.crt"),
			leafPath:  filepath.Join(tmpDir, "leaf.crt"),
			wantError: "error writing root certificate: failed to create file",
		},
		{
			name:      "leaf_cert_write_error",
			rootPath:  filepath.Join(tmpDir, "root.crt"),
			leafPath:  filepath.Join(readOnlyDir, "leaf.crt"),
			wantError: "error writing leaf certificate: failed to create file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CreateCertificates(mockSigner, config, rootTmplPath, leafTmplPath, tt.rootPath, tt.leafPath, "", "", "")
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantError)
		})
	}
}

func TestCreateCertificatesWithSigningErrors(t *testing.T) {
	defer func() { InitKMS = originalInitKMS }()

	InitKMS = func(_ context.Context, config KMSConfig) (signature.SignerVerifier, error) {
		if config.LeafKeyID == "test-leaf-key" {
			return nil, fmt.Errorf("leaf signing error")
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return &mockSignerVerifier{
			key: key,
			publicKeyFunc: func() (crypto.PublicKey, error) {
				return &key.PublicKey, nil
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
			signFunc: func(rand io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
				return ecdsa.SignASN1(rand, key, digest)
			},
		}, nil
	}

	tests := []struct {
		name      string
		setup     func() (*mockSignerVerifier, *mockSignerVerifier)
		wantError string
	}{
		{
			name: "leaf_signing_error",
			setup: func() (*mockSignerVerifier, *mockSignerVerifier) {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				return &mockSignerVerifier{
					key: key,
					publicKeyFunc: func() (crypto.PublicKey, error) {
						return &key.PublicKey, nil
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
					signFunc: func(rand io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
						return ecdsa.SignASN1(rand, key, digest)
					},
				}, nil
			},
			wantError: "leaf signing error",
		},
		{
			name: "root_signing_error",
			setup: func() (*mockSignerVerifier, *mockSignerVerifier) {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				rootSigner := &mockSignerVerifier{
					key: key,
					publicKeyFunc: func() (crypto.PublicKey, error) {
						return nil, fmt.Errorf("root signing error")
					},
				}
				return rootSigner, nil
			},
			wantError: "error getting root public key: root signing error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, err := os.MkdirTemp("", "cert-test-*")
			require.NoError(t, err)
			defer os.RemoveAll(tmpDir)

			rootTmplPath := filepath.Join(tmpDir, "root-template.json")
			leafTmplPath := filepath.Join(tmpDir, "leaf-template.json")

			rootTemplate := `{
				"subject": {
					"commonName": "Test Root CA"
				},
				"issuer": {
					"commonName": "Test Root CA"
				},
				"certLife": "8760h",
				"keyUsage": ["certSign", "crlSign"],
				"basicConstraints": {
					"isCA": true,
					"maxPathLen": 1
				}
			}`

			leafTemplate := `{
				"subject": {
					"commonName": "Test Leaf"
				},
				"issuer": {
					"commonName": "Test Root CA"
				},
				"certLife": "8760h",
				"keyUsage": ["digitalSignature"],
				"extKeyUsage": ["TimeStamping"],
				"basicConstraints": {
					"isCA": false
				}
			}`

			err = os.WriteFile(rootTmplPath, []byte(rootTemplate), 0644)
			require.NoError(t, err)
			err = os.WriteFile(leafTmplPath, []byte(leafTemplate), 0644)
			require.NoError(t, err)

			rootSigner, _ := tt.setup()

			err = CreateCertificates(rootSigner, KMSConfig{
				Type:      "mock",
				RootKeyID: "test-root-key",
				LeafKeyID: "test-leaf-key",
			},
				rootTmplPath,
				leafTmplPath,
				filepath.Join(tmpDir, "root.crt"),
				filepath.Join(tmpDir, "leaf.crt"),
				"", "", "")

			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantError)
		})
	}
}

func TestInitKMSWithDifferentProviders(t *testing.T) {
	tests := []struct {
		name      string
		config    KMSConfig
		wantError string
	}{
		{
			name: "AWS KMS missing region",
			config: KMSConfig{
				Type:      "awskms",
				RootKeyID: "alias/test-key",
				LeafKeyID: "alias/test-key",
				Options:   map[string]string{},
			},
			wantError: "aws-region is required",
		},
		{
			name: "GCP KMS invalid key format",
			config: KMSConfig{
				Type:      "gcpkms",
				RootKeyID: "invalid-key-format",
				LeafKeyID: "invalid-key-format",
				Options: map[string]string{
					"gcp-credentials-file": "/path/to/creds.json",
				},
			},
			wantError: "must start with 'projects/'",
		},
		{
			name: "Azure KMS missing tenant ID",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "azurekms:name=test-key;vault=test-vault",
				LeafKeyID: "azurekms:name=test-key;vault=test-vault",
				Options:   map[string]string{},
			},
			wantError: "azure-tenant-id is required",
		},
		{
			name: "HashiVault KMS missing token",
			config: KMSConfig{
				Type:      "hashivault",
				RootKeyID: "test-key",
				LeafKeyID: "test-key",
				Options: map[string]string{
					"vault-address": "http://vault:8200",
				},
			},
			wantError: "vault-token is required",
		},
		{
			name: "Unsupported KMS type",
			config: KMSConfig{
				Type:      "unsupported",
				RootKeyID: "test-key",
				LeafKeyID: "test-key",
				Options:   map[string]string{},
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
}

func TestWriteCertificateToFileErrors(t *testing.T) {
	cert := &x509.Certificate{
		Raw: []byte("test certificate"),
	}

	tests := []struct {
		name      string
		filename  string
		wantError string
	}{
		{
			name:      "invalid path",
			filename:  "/nonexistent/directory/cert.pem",
			wantError: "failed to create file",
		},
		{
			name:      "empty filename",
			filename:  "",
			wantError: "failed to create file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := WriteCertificateToFile(cert, tt.filename)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantError)
		})
	}
}

func TestCreateCertificatesWithMockSigner(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cert-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	rootTemplate := filepath.Join(tmpDir, "root-template.json")
	leafTemplate := filepath.Join(tmpDir, "leaf-template.json")
	rootCert := filepath.Join(tmpDir, "root.pem")
	leafCert := filepath.Join(tmpDir, "leaf.pem")

	rootTmplContent := `{
		"subject": {
			"commonName": "Test Root CA"
		},
		"issuer": {
			"commonName": "Test Root CA"
		},
		"certLife": "8760h",
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 1
		}
	}`

	leafTmplContent := `{
		"subject": {
			"commonName": "Test Leaf"
		},
		"certLife": "8760h",
		"keyUsage": ["digitalSignature"],
		"extKeyUsage": ["CodeSigning"],
		"basicConstraints": {
			"isCA": false
		}
	}`

	err = os.WriteFile(rootTemplate, []byte(rootTmplContent), 0600)
	require.NoError(t, err)
	err = os.WriteFile(leafTemplate, []byte(leafTmplContent), 0600)
	require.NoError(t, err)

	mockSV := &mockSignerVerifier{
		publicKeyFunc: func() (crypto.PublicKey, error) {
			return nil, fmt.Errorf("mock public key error")
		},
	}

	config := KMSConfig{
		Type:      "mock",
		RootKeyID: "test-root-key",
		LeafKeyID: "test-leaf-key",
	}

	err = CreateCertificates(mockSV, config, rootTemplate, leafTemplate, rootCert, leafCert, "", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mock public key error")
}
