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
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.step.sm/crypto/kms/apiv1"
)

type mockKMSProvider struct {
	keys map[string]crypto.Signer
}

func newMockKMSProvider() *mockKMSProvider {
	keys := make(map[string]crypto.Signer)
	for _, id := range []string{"root-key", "intermediate-key", "leaf-key"} {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		keys[id] = priv
	}
	return &mockKMSProvider{keys: keys}
}

func (m *mockKMSProvider) CreateKey(*apiv1.CreateKeyRequest) (*apiv1.CreateKeyResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockKMSProvider) CreateSigner(req *apiv1.CreateSignerRequest) (crypto.Signer, error) {
	key, ok := m.keys[req.SigningKey]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", req.SigningKey)
	}
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
			name: "GCP_KMS_invalid_root_key_ID",
			config: KMSConfig{
				Type:      "gcpkms",
				RootKeyID: "invalid-key-id",
			},
			wantError: "gcpkms RootKeyID must start with 'projects/'",
		},
		{
			name: "GCP_KMS_invalid_intermediate_key_ID",
			config: KMSConfig{
				Type:              "gcpkms",
				RootKeyID:         "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1",
				IntermediateKeyID: "invalid-key-id",
			},
			wantError: "gcpkms IntermediateKeyID must start with 'projects/'",
		},
		{
			name: "GCP_KMS_invalid_leaf_key_ID",
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
				RootKeyID: "projects/test-project",
			},
			wantError: "gcpkms RootKeyID must contain '/locations/'",
		},
		{
			name: "Azure_KMS_missing_tenant_ID",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "azurekms:name=my-key;vault=my-vault",
				Options:   map[string]string{},
			},
			wantError: "tenant-id is required for Azure KMS",
		},
		{
			name: "Azure_KMS_missing_vault_parameter",
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
			name: "unsupported KMS type",
			config: KMSConfig{
				Type:      "invalidkms",
				RootKeyID: "key-id",
			},
			wantError: "unsupported KMS type",
		},
		{
			name: "aws_kms_invalid_arn_format",
			config: KMSConfig{
				Type:      "awskms",
				Region:    "us-west-2",
				RootKeyID: "arn:aws:kms:us-west-2:invalid",
			},
			wantError: "invalid AWS KMS ARN format for RootKeyID",
		},
		{
			name: "aws_kms_region_mismatch",
			config: KMSConfig{
				Type:      "awskms",
				Region:    "us-west-2",
				RootKeyID: "arn:aws:kms:us-east-1:123456789012:key/test-key",
			},
			wantError: "region in ARN (us-east-1) does not match configured region (us-west-2)",
		},
		{
			name: "aws_kms_empty_alias",
			config: KMSConfig{
				Type:      "awskms",
				Region:    "us-west-2",
				RootKeyID: "alias/",
			},
			wantError: "alias name cannot be empty for RootKeyID",
		},
		{
			name: "azure_kms_empty_key_name",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "azurekms:name=;vault=test-vault",
				Options: map[string]string{
					"tenant-id": "test-tenant",
				},
			},
			wantError: "key name cannot be empty for RootKeyID",
		},
		{
			name: "azure_kms_empty_vault_name",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "azurekms:name=test-key;vault=",
				Options: map[string]string{
					"tenant-id": "test-tenant",
				},
			},
			wantError: "vault name cannot be empty for RootKeyID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKMSConfig(tt.config)
			if tt.wantError != "" {
				if err == nil {
					t.Error("Expected error but got none")
				} else if !strings.Contains(err.Error(), tt.wantError) {
					t.Errorf("Expected error containing %q, got %q", tt.wantError, err.Error())
				}
			} else if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestCreateCertificates(t *testing.T) {
	t.Run("TSA without intermediate", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "cert-test-*")
		if err != nil {
			t.Fatalf("Failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		rootTemplate := filepath.Join(tmpDir, "root.json")
		err = os.WriteFile(rootTemplate, []byte(`{
			"subject": {
				"commonName": "Test Root CA"
			},
			"issuer": {
				"commonName": "Test Root CA"
			},
			"keyUsage": ["certSign", "crlSign"],
			"basicConstraints": {
				"isCA": true,
				"maxPathLen": 1
			},
			"notBefore": "2024-01-01T00:00:00Z",
			"notAfter": "2025-01-01T00:00:00Z"
		}`), 0600)
		if err != nil {
			t.Fatalf("Failed to write root template: %v", err)
		}

		leafTemplate := filepath.Join(tmpDir, "leaf.json")
		err = os.WriteFile(leafTemplate, []byte(`{
			"subject": {
				"commonName": "Test TSA"
			},
			"issuer": {
				"commonName": "Test Root CA"
			},
			"keyUsage": ["digitalSignature"],
			"basicConstraints": {
				"isCA": false
			},
			"extKeyUsage": ["timeStamping"],
			"notBefore": "2024-01-01T00:00:00Z",
			"notAfter": "2025-01-01T00:00:00Z"
		}`), 0600)
		if err != nil {
			t.Fatalf("Failed to write leaf template: %v", err)
		}

		config := KMSConfig{
			Type:      "test",
			RootKeyID: "root-key",
			LeafKeyID: "leaf-key",
		}

		outDir := filepath.Join(tmpDir, "out")
		err = os.MkdirAll(outDir, 0755)
		if err != nil {
			t.Fatalf("Failed to create output directory: %v", err)
		}

		kms := newMockKMSProvider()
		err = CreateCertificates(kms, config,
			rootTemplate, leafTemplate,
			filepath.Join(outDir, "root.crt"), filepath.Join(outDir, "leaf.crt"),
			"", "", "")
		if err != nil {
			t.Fatalf("Failed to create certificates: %v", err)
		}

		verifyGeneratedCertificates(t, outDir)
	})

	t.Run("TSA with intermediate", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "cert-test-*")
		if err != nil {
			t.Fatalf("Failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		rootTemplate := filepath.Join(tmpDir, "root.json")
		err = os.WriteFile(rootTemplate, []byte(`{
			"subject": {
				"commonName": "Test Root CA"
			},
			"issuer": {
				"commonName": "Test Root CA"
			},
			"keyUsage": ["certSign", "crlSign"],
			"basicConstraints": {
				"isCA": true,
				"maxPathLen": 1
			},
			"notBefore": "2024-01-01T00:00:00Z",
			"notAfter": "2025-01-01T00:00:00Z"
		}`), 0600)
		if err != nil {
			t.Fatalf("Failed to write root template: %v", err)
		}

		intermediateTemplate := filepath.Join(tmpDir, "intermediate.json")
		err = os.WriteFile(intermediateTemplate, []byte(`{
			"subject": {
				"commonName": "Test Intermediate CA"
			},
			"issuer": {
				"commonName": "Test Root CA"
			},
			"keyUsage": ["certSign", "crlSign"],
			"basicConstraints": {
				"isCA": true,
				"maxPathLen": 0
			},
			"notBefore": "2024-01-01T00:00:00Z",
			"notAfter": "2025-01-01T00:00:00Z"
		}`), 0600)
		if err != nil {
			t.Fatalf("Failed to write intermediate template: %v", err)
		}

		leafTemplate := filepath.Join(tmpDir, "leaf.json")
		err = os.WriteFile(leafTemplate, []byte(`{
			"subject": {
				"commonName": "Test TSA"
			},
			"issuer": {
				"commonName": "Test Intermediate CA"
			},
			"keyUsage": ["digitalSignature"],
			"basicConstraints": {
				"isCA": false
			},
			"extKeyUsage": ["timeStamping"],
			"notBefore": "2024-01-01T00:00:00Z",
			"notAfter": "2025-01-01T00:00:00Z"
		}`), 0600)
		if err != nil {
			t.Fatalf("Failed to write leaf template: %v", err)
		}

		config := KMSConfig{
			Type:              "test",
			RootKeyID:         "root-key",
			IntermediateKeyID: "intermediate-key",
			LeafKeyID:         "leaf-key",
		}

		outDir := filepath.Join(tmpDir, "out")
		err = os.MkdirAll(outDir, 0755)
		if err != nil {
			t.Fatalf("Failed to create output directory: %v", err)
		}

		kms := newMockKMSProvider()
		err = CreateCertificates(kms, config,
			rootTemplate, leafTemplate,
			filepath.Join(outDir, "root.crt"), filepath.Join(outDir, "leaf.crt"),
			"intermediate-key", intermediateTemplate, filepath.Join(outDir, "intermediate.crt"))
		if err != nil {
			t.Fatalf("Failed to create certificates: %v", err)
		}

		verifyGeneratedCertificates(t, outDir)
	})

	t.Run("invalid root template path", func(t *testing.T) {
		kms := newMockKMSProvider()
		config := KMSConfig{
			Type:      "test",
			RootKeyID: "root-key",
			LeafKeyID: "leaf-key",
		}

		err := CreateCertificates(kms, config,
			"/nonexistent/root.json", "/nonexistent/leaf.json",
			"/nonexistent/root.crt", "/nonexistent/leaf.crt",
			"", "", "")
		if err == nil {
			t.Error("Expected error but got none")
		}
		if !strings.Contains(err.Error(), "error reading template file") {
			t.Errorf("Expected error containing 'error reading template file', got %v", err)
		}
	})
}

func verifyGeneratedCertificates(t *testing.T, outDir string) {
	files := []string{
		"root.crt",
		"leaf.crt",
	}

	intermediateExists := false
	intermediatePath := filepath.Join(outDir, "intermediate.crt")
	if _, err := os.Stat(intermediatePath); err == nil {
		intermediateExists = true
		files = append(files, "intermediate.crt")
	}

	for _, f := range files {
		path := filepath.Join(outDir, f)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("Expected file %s does not exist", f)
		}
	}

	rootCertPath := filepath.Join(outDir, "root.crt")
	rootCertBytes, err := os.ReadFile(rootCertPath)
	if err != nil {
		t.Fatalf("Failed to read root certificate: %v", err)
	}

	rootBlock, _ := pem.Decode(rootCertBytes)
	if rootBlock == nil {
		t.Fatal("Failed to decode root certificate PEM")
	}

	rootCert, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse root certificate: %v", err)
	}

	if rootCert.Subject.CommonName != "Test Root CA" {
		t.Errorf("Expected root CN %q, got %q", "Test Root CA", rootCert.Subject.CommonName)
	}

	if !rootCert.IsCA {
		t.Error("Expected root certificate to be CA")
	}

	var intermediateCert *x509.Certificate
	if intermediateExists {
		intermediateCertBytes, err := os.ReadFile(intermediatePath)
		if err != nil {
			t.Fatalf("Failed to read intermediate certificate: %v", err)
		}

		intermediateBlock, _ := pem.Decode(intermediateCertBytes)
		if intermediateBlock == nil {
			t.Fatal("Failed to decode intermediate certificate PEM")
		}

		intermediateCert, err = x509.ParseCertificate(intermediateBlock.Bytes)
		if err != nil {
			t.Fatalf("Failed to parse intermediate certificate: %v", err)
		}

		if intermediateCert.Subject.CommonName != "Test Intermediate CA" {
			t.Errorf("Expected intermediate CN %q, got %q", "Test Intermediate CA", intermediateCert.Subject.CommonName)
		}

		if !intermediateCert.IsCA {
			t.Error("Expected intermediate certificate to be CA")
		}
	}

	leafCertPath := filepath.Join(outDir, "leaf.crt")
	leafCertBytes, err := os.ReadFile(leafCertPath)
	if err != nil {
		t.Fatalf("Failed to read leaf certificate: %v", err)
	}

	leafBlock, _ := pem.Decode(leafCertBytes)
	if leafBlock == nil {
		t.Fatal("Failed to decode leaf certificate PEM")
	}

	leafCert, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse leaf certificate: %v", err)
	}

	if leafCert.Subject.CommonName != "Test TSA" {
		t.Errorf("Expected leaf CN %q, got %q", "Test TSA", leafCert.Subject.CommonName)
	}

	if leafCert.IsCA {
		t.Error("Expected leaf certificate not to be CA")
	}

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	intermediates := x509.NewCertPool()
	if intermediateCert != nil {
		intermediates.AddCert(intermediateCert)
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageTimeStamping,
		},
	}

	if _, err := leafCert.Verify(opts); err != nil {
		t.Errorf("Failed to verify certificate chain: %v", err)
	}
}

func TestInitKMS(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "kms-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	credsFile := filepath.Join(tmpDir, "test-credentials.json")
	err = os.WriteFile(credsFile, []byte(fmt.Sprintf(`{
		"type": "service_account",
		"project_id": "test-project",
		"private_key_id": "test-key-id",
		"private_key": %q,
		"client_email": "test@test-project.iam.gserviceaccount.com",
		"client_id": "123456789",
		"auth_uri": "https://accounts.google.com/o/oauth2/auth",
		"token_uri": "https://oauth2.googleapis.com/token",
		"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
		"client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/test@test-project.iam.gserviceaccount.com"
	}`, string(privKeyPEM))), 0600)
	if err != nil {
		t.Fatalf("Failed to write credentials file: %v", err)
	}

	ctx := context.Background()
	tests := []struct {
		name      string
		config    KMSConfig
		wantError bool
		errMsg    string
	}{
		{
			name: "valid AWS KMS config",
			config: KMSConfig{
				Type:      "awskms",
				Region:    "us-west-2",
				RootKeyID: "arn:aws:kms:us-west-2:123456789012:key/test-key",
				LeafKeyID: "arn:aws:kms:us-west-2:123456789012:key/leaf-key",
				Options:   map[string]string{},
			},
			wantError: false,
		},
		{
			name: "valid GCP KMS config",
			config: KMSConfig{
				Type:      "gcpkms",
				RootKeyID: "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1",
				LeafKeyID: "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/leaf-key/cryptoKeyVersions/1",
				Options: map[string]string{
					"credentials-file": credsFile,
				},
			},
			wantError: false,
		},
		{
			name: "valid Azure KMS config",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "azurekms:name=test-key;vault=test-vault",
				LeafKeyID: "azurekms:name=leaf-key;vault=test-vault",
				Options: map[string]string{
					"tenant-id": "test-tenant",
				},
			},
			wantError: false,
		},
		{
			name: "AWS KMS missing region",
			config: KMSConfig{
				Type:      "awskms",
				RootKeyID: "arn:aws:kms:us-west-2:123456789012:key/test-key",
			},
			wantError: true,
			errMsg:    "region is required for AWS KMS",
		},
		{
			name: "GCP KMS invalid credentials",
			config: KMSConfig{
				Type:      "gcpkms",
				RootKeyID: "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1",
				Options: map[string]string{
					"credentials-file": "/nonexistent/credentials.json",
				},
			},
			wantError: true,
			errMsg:    "credentials file not found",
		},
		{
			name: "Azure KMS missing tenant ID",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "azurekms:name=test-key;vault=test-vault",
				Options:   map[string]string{},
			},
			wantError: true,
			errMsg:    "tenant-id is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			km, err := InitKMS(ctx, tt.config)
			if tt.wantError {
				if err == nil {
					t.Error("expected error but got nil")
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errMsg)
				}
				if km != nil {
					t.Error("expected nil KMS but got non-nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if km == nil {
					t.Error("expected non-nil KMS but got nil")
				}
			}
		})
	}
}

func TestValidateTemplatePath(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		setup     func() string
		wantError string
	}{
		{
			name:      "nonexistent file",
			path:      "/nonexistent/template.json",
			wantError: "template not found",
		},
		{
			name: "wrong extension",
			path: "template.txt",
			setup: func() string {
				f, err := os.CreateTemp("", "template.txt")
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return f.Name()
			},
			wantError: "must have .json extension",
		},
		{
			name: "valid JSON template",
			path: "valid.json",
			setup: func() string {
				f, err := os.CreateTemp("", "template*.json")
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				err = os.WriteFile(f.Name(), []byte(`{"key": "value"}`), 0600)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return f.Name()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.path
			if tt.setup != nil {
				path = tt.setup()
				defer os.Remove(path)
			}

			err := ValidateTemplatePath(path)
			if tt.wantError != "" {
				if err == nil {
					t.Errorf("expected error, got nil")
				} else if !strings.Contains(err.Error(), tt.wantError) {
					t.Errorf("error %q should contain %q", err.Error(), tt.wantError)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestCreateCertificatesErrors(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T) (string, KMSConfig, apiv1.KeyManager)
		wantError string
	}{
		{
			name: "error creating intermediate signer",
			setup: func(t *testing.T) (string, KMSConfig, apiv1.KeyManager) {
				tmpDir, err := os.MkdirTemp("", "cert-test-*")
				if err != nil {
					t.Fatalf("Failed to create temp dir: %v", err)
				}

				rootTemplate := filepath.Join(tmpDir, "root.json")
				err = os.WriteFile(rootTemplate, []byte(`{
					"subject": {"commonName": "Test Root CA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 1},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				if err != nil {
					t.Fatalf("Failed to write root template: %v", err)
				}

				intermediateTemplate := filepath.Join(tmpDir, "intermediate.json")
				err = os.WriteFile(intermediateTemplate, []byte(`{
					"subject": {"commonName": "Test Intermediate CA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 0},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				if err != nil {
					t.Fatalf("Failed to write intermediate template: %v", err)
				}

				leafTemplate := filepath.Join(tmpDir, "leaf.json")
				err = os.WriteFile(leafTemplate, []byte(`{
					"subject": {"commonName": "Test TSA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["digitalSignature"],
					"basicConstraints": {"isCA": false},
					"extKeyUsage": ["timeStamping"],
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				if err != nil {
					t.Fatalf("Failed to write leaf template: %v", err)
				}

				config := KMSConfig{
					Type:              "test",
					RootKeyID:         "root-key",
					IntermediateKeyID: "nonexistent-key",
					LeafKeyID:         "leaf-key",
				}

				return tmpDir, config, newMockKMSProvider()
			},
			wantError: "error creating intermediate signer",
		},
		{
			name: "error creating leaf signer",
			setup: func(t *testing.T) (string, KMSConfig, apiv1.KeyManager) {
				tmpDir, err := os.MkdirTemp("", "cert-test-*")
				if err != nil {
					t.Fatalf("Failed to create temp dir: %v", err)
				}

				rootTemplate := filepath.Join(tmpDir, "root.json")
				err = os.WriteFile(rootTemplate, []byte(`{
					"subject": {"commonName": "Test Root CA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 1},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				if err != nil {
					t.Fatalf("Failed to write root template: %v", err)
				}

				leafTemplate := filepath.Join(tmpDir, "leaf.json")
				err = os.WriteFile(leafTemplate, []byte(`{
					"subject": {"commonName": "Test TSA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["digitalSignature"],
					"basicConstraints": {"isCA": false},
					"extKeyUsage": ["timeStamping"],
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				if err != nil {
					t.Fatalf("Failed to write leaf template: %v", err)
				}

				config := KMSConfig{
					Type:      "test",
					RootKeyID: "root-key",
					LeafKeyID: "nonexistent-key",
				}

				return tmpDir, config, newMockKMSProvider()
			},
			wantError: "error creating leaf signer",
		},
		{
			name: "error creating root certificate",
			setup: func(t *testing.T) (string, KMSConfig, apiv1.KeyManager) {
				tmpDir, err := os.MkdirTemp("", "cert-test-*")
				if err != nil {
					t.Fatalf("Failed to create temp dir: %v", err)
				}

				rootTemplate := filepath.Join(tmpDir, "root.json")
				err = os.WriteFile(rootTemplate, []byte(`{
					"subject": {},
					"issuer": {},
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				if err != nil {
					t.Fatalf("Failed to write root template: %v", err)
				}

				leafTemplate := filepath.Join(tmpDir, "leaf.json")
				err = os.WriteFile(leafTemplate, []byte(`{
					"subject": {"commonName": "Test TSA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["digitalSignature"],
					"basicConstraints": {"isCA": false},
					"extKeyUsage": ["timeStamping"],
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				if err != nil {
					t.Fatalf("Failed to write leaf template: %v", err)
				}

				config := KMSConfig{
					Type:      "test",
					RootKeyID: "root-key",
					LeafKeyID: "leaf-key",
				}

				return tmpDir, config, newMockKMSProvider()
			},
			wantError: "error parsing root template: template validation error: notBefore time must be specified",
		},
		{
			name: "error writing certificates",
			setup: func(t *testing.T) (string, KMSConfig, apiv1.KeyManager) {
				tmpDir, err := os.MkdirTemp("", "cert-test-*")
				if err != nil {
					t.Fatalf("Failed to create temp dir: %v", err)
				}

				rootTemplate := filepath.Join(tmpDir, "root.json")
				err = os.WriteFile(rootTemplate, []byte(`{
					"subject": {"commonName": "Test Root CA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 1},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				if err != nil {
					t.Fatalf("Failed to write root template: %v", err)
				}

				outDir := filepath.Join(tmpDir, "out")
				err = os.MkdirAll(outDir, 0444)
				if err != nil {
					t.Fatalf("Failed to create output directory: %v", err)
				}

				config := KMSConfig{
					Type:      "test",
					RootKeyID: "root-key",
					LeafKeyID: "leaf-key",
				}

				return tmpDir, config, newMockKMSProvider()
			},
			wantError: "error writing root certificate",
		},
		{
			name: "error with nonexistent signer",
			setup: func(t *testing.T) (string, KMSConfig, apiv1.KeyManager) {
				tmpDir, err := os.MkdirTemp("", "cert-test-*")
				if err != nil {
					t.Fatalf("Failed to create temp dir: %v", err)
				}

				rootTemplate := filepath.Join(tmpDir, "root.json")
				err = os.WriteFile(rootTemplate, []byte(`{
					"subject": {"commonName": "Test Root CA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 1},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				if err != nil {
					t.Fatalf("Failed to write root template: %v", err)
				}

				config := KMSConfig{
					Type:      "test",
					RootKeyID: "nonexistent-key",
					LeafKeyID: "leaf-key",
				}

				return tmpDir, config, newMockKMSProvider()
			},
			wantError: "error creating root signer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, config, kms := tt.setup(t)
			defer os.RemoveAll(tmpDir)

			outDir := filepath.Join(tmpDir, "out")
			err := os.MkdirAll(outDir, 0755)
			if err != nil {
				t.Fatalf("Failed to create output directory: %v", err)
			}

			var intermediateKeyID string
			if tt.name == "error creating intermediate signer" {
				intermediateKeyID = "nonexistent-key"
			}

			err = CreateCertificates(kms, config,
				filepath.Join(tmpDir, "root.json"),
				filepath.Join(tmpDir, "leaf.json"),
				filepath.Join(outDir, "root.crt"),
				filepath.Join(outDir, "leaf.crt"),
				intermediateKeyID,
				filepath.Join(tmpDir, "intermediate.json"),
				filepath.Join(outDir, "intermediate.crt"))

			if tt.wantError != "" {
				if err == nil {
					t.Error("Expected error but got none")
				} else if !strings.Contains(err.Error(), tt.wantError) {
					t.Errorf("Expected error containing %q, got %q", tt.wantError, err.Error())
				}
			} else if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}
