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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTemplate(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cert-template-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	parent := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "Parent CA",
		},
	}

	tests := []struct {
		name      string
		template  string
		wantError string
	}{
		{
			name: "valid template with duration-based validity",
			template: `{
				"subject": {
					"commonName": "Test CA"
				},
				"issuer": {
					"commonName": "Parent CA"
				},
				"certLife": "8760h",
				"keyUsage": ["certSign", "crlSign"],
				"basicConstraints": {
					"isCA": true,
					"maxPathLen": 1
				}
			}`,
			wantError: "",
		},
		{
			name: "invalid certLife format",
			template: `{
				"subject": {
					"commonName": "Test CA"
				},
				"issuer": {
					"commonName": "Parent CA"
				},
				"certLife": "invalid",
				"keyUsage": ["certSign", "crlSign"],
				"basicConstraints": {
					"isCA": true,
					"maxPathLen": 1
				}
			}`,
			wantError: "invalid certLife format",
		},
		{
			name: "missing certLife",
			template: `{
				"subject": {
					"commonName": "Test CA"
				},
				"issuer": {
					"commonName": "Parent CA"
				},
				"keyUsage": ["certSign", "crlSign"],
				"basicConstraints": {
					"isCA": true,
					"maxPathLen": 1
				}
			}`,
			wantError: "certLife must be specified",
		},
		{
			name: "negative certLife",
			template: `{
				"subject": {
					"commonName": "Test CA"
				},
				"issuer": {
					"commonName": "Parent CA"
				},
				"certLife": "-8760h",
				"keyUsage": ["certSign", "crlSign"],
				"basicConstraints": {
					"isCA": true,
					"maxPathLen": 1
				}
			}`,
			wantError: "certLife must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			templateFile := filepath.Join(tmpDir, "template.json")
			err := os.WriteFile(templateFile, []byte(tt.template), 0600)
			require.NoError(t, err)

			cert, err := ParseTemplate(templateFile, parent)
			if tt.wantError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, cert)
			}
		})
	}
}

func TestParseTemplateWithInvalidExtensions(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cert-template-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	content := `{
		"subject": {"commonName": "Test TSA"},
		"issuer": {"commonName": "Test TSA"},
		"certLife": "8760h",
		"keyUsage": ["digitalSignature"],
		"basicConstraints": {"isCA": false},
		"extensions": [
			{
				"id": "2.5.29.37",
				"critical": true,
				"value": "invalid-base64"
			}
		]
	}`

	tmpFile := filepath.Join(tmpDir, "template.json")
	err = os.WriteFile(tmpFile, []byte(content), 0600)
	require.NoError(t, err)

	parent := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "Parent CA",
		},
	}

	cert, err := ParseTemplate(tmpFile, parent)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error decoding extension value")
	assert.Nil(t, cert)
}

func TestValidateTemplate(t *testing.T) {
	tests := []struct {
		name      string
		template  *CertificateTemplate
		parent    *x509.Certificate
		wantError string
	}{
		{
			name: "valid root CA template",
			template: &CertificateTemplate{
				Subject: struct {
					Country            []string `json:"country,omitempty"`
					Organization       []string `json:"organization,omitempty"`
					OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
					CommonName         string   `json:"commonName"`
				}{
					CommonName: "Test Root CA",
				},
				Issuer: struct {
					CommonName string `json:"commonName"`
				}{
					CommonName: "Test Root CA",
				},
				CertLifetime: "8760h",
				KeyUsage:     []string{"certSign", "crlSign"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{
					IsCA:       true,
					MaxPathLen: 1,
				},
			},
		},
		{
			name: "valid intermediate CA template",
			template: &CertificateTemplate{
				Subject: struct {
					Country            []string `json:"country,omitempty"`
					Organization       []string `json:"organization,omitempty"`
					OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
					CommonName         string   `json:"commonName"`
				}{
					CommonName: "Test Intermediate CA",
				},
				Issuer: struct {
					CommonName string `json:"commonName"`
				}{
					CommonName: "Test Root CA",
				},
				CertLifetime: "8760h",
				KeyUsage:     []string{"certSign", "crlSign"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{
					IsCA:       true,
					MaxPathLen: 0,
				},
			},
			parent: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "Test Root CA",
				},
			},
		},
		{
			name: "valid leaf template",
			template: &CertificateTemplate{
				Subject: struct {
					Country            []string `json:"country,omitempty"`
					Organization       []string `json:"organization,omitempty"`
					OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
					CommonName         string   `json:"commonName"`
				}{
					CommonName: "Test Leaf",
				},
				Issuer: struct {
					CommonName string `json:"commonName"`
				}{
					CommonName: "Test Intermediate CA",
				},
				CertLifetime: "8760h",
				KeyUsage:     []string{"digitalSignature"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{
					IsCA: false,
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
			parent: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "Test Intermediate CA",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTemplate(tt.template, tt.parent)
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

func TestValidateTemplateWithMockKMS(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockSigner := &mockSignerVerifier{
		key: privKey,
	}

	parent := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "Parent CA",
		},
	}

	tests := []struct {
		name      string
		template  *CertificateTemplate
		parent    *x509.Certificate
		signer    signature.SignerVerifier
		wantError string
	}{
		{
			name: "valid template",
			template: &CertificateTemplate{
				Subject: struct {
					Country            []string `json:"country,omitempty"`
					Organization       []string `json:"organization,omitempty"`
					OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
					CommonName         string   `json:"commonName"`
				}{
					CommonName: "Test TSA",
				},
				Issuer: struct {
					CommonName string `json:"commonName"`
				}{
					CommonName: "Test TSA",
				},
				CertLifetime: "8760h",
				KeyUsage:     []string{"digitalSignature"},
				Extensions: []struct {
					ID       string `json:"id"`
					Critical bool   `json:"critical"`
					Value    string `json:"value"`
				}{
					{
						ID:       "2.5.29.37",
						Critical: true,
						Value:    base64.StdEncoding.EncodeToString([]byte{0x30, 0x24, 0x30, 0x22, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08}),
					},
				},
			},
			parent: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "Test TSA",
				},
			},
			signer: mockSigner,
		},
		{
			name: "missing certLife",
			template: &CertificateTemplate{
				Subject: struct {
					Country            []string `json:"country,omitempty"`
					Organization       []string `json:"organization,omitempty"`
					OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
					CommonName         string   `json:"commonName"`
				}{
					CommonName: "Test TSA",
				},
				Issuer: struct {
					CommonName string `json:"commonName"`
				}{
					CommonName: "Test TSA",
				},
				KeyUsage: []string{"digitalSignature"},
			},
			parent:    parent,
			signer:    mockSigner,
			wantError: "certLife must be specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTemplate(tt.template, tt.parent)
			if tt.wantError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestParseTemplateWithInvalidJSON(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		wantError string
	}{
		{
			name: "invalid JSON structure",
			content: `{
				"subject": {
					"commonName": "Test"
				},
				"keyUsage": ["certSign", // missing closing bracket
				"certLife": "8760h"
			}`,
			wantError: "invalid character",
		},
		{
			name:      "empty template",
			content:   `{}`,
			wantError: "certLife must be specified",
		},
		{
			name: "missing required fields",
			content: `{
				"subject": {},
				"certLife": "8760h"
			}`,
			wantError: "subject.commonName cannot be empty",
		},
		{
			name: "invalid key usage",
			content: `{
				"subject": {
					"commonName": "Test"
				},
				"issuer": {
					"commonName": "Test"
				},
				"certLife": "8760h",
				"keyUsage": ["invalidUsage"],
				"basicConstraints": {
					"isCA": false
				}
			}`,
			wantError: "timestamp authority certificate must have digitalSignature key usage",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "cert-template-*.json")
			require.NoError(t, err)
			defer os.Remove(tmpFile.Name())

			err = os.WriteFile(tmpFile.Name(), []byte(tt.content), 0600)
			require.NoError(t, err)

			_, err = ParseTemplate(tmpFile.Name(), nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantError)
		})
	}
}

func TestSetCertificateUsagesComprehensive(t *testing.T) {
	tests := []struct {
		name              string
		keyUsages         []string
		extKeyUsages      []string
		expectedKeyUsage  x509.KeyUsage
		expectedExtUsages []x509.ExtKeyUsage
	}{
		{
			name:              "empty usages",
			keyUsages:         []string{},
			extKeyUsages:      []string{},
			expectedKeyUsage:  0,
			expectedExtUsages: nil,
		},
		{
			name:              "single key usage",
			keyUsages:         []string{"certSign"},
			extKeyUsages:      []string{},
			expectedKeyUsage:  x509.KeyUsageCertSign,
			expectedExtUsages: nil,
		},
		{
			name:              "single ext usage",
			keyUsages:         []string{},
			extKeyUsages:      []string{"CodeSigning"},
			expectedKeyUsage:  0,
			expectedExtUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		},
		{
			name:              "multiple key usages",
			keyUsages:         []string{"certSign", "crlSign", "digitalSignature"},
			extKeyUsages:      []string{},
			expectedKeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
			expectedExtUsages: nil,
		},
		{
			name:              "multiple ext usages",
			keyUsages:         []string{},
			extKeyUsages:      []string{"CodeSigning", "TimeStamping"},
			expectedKeyUsage:  0,
			expectedExtUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageTimeStamping},
		},
		{
			name:              "both key and ext usages",
			keyUsages:         []string{"certSign", "digitalSignature"},
			extKeyUsages:      []string{"CodeSigning", "TimeStamping"},
			expectedKeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
			expectedExtUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageTimeStamping},
		},
		{
			name:              "invalid usages",
			keyUsages:         []string{"invalidKeyUsage"},
			extKeyUsages:      []string{"invalidExtUsage"},
			expectedKeyUsage:  0,
			expectedExtUsages: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{}
			SetCertificateUsages(cert, tt.keyUsages, tt.extKeyUsages)
			assert.Equal(t, tt.expectedKeyUsage, cert.KeyUsage)
			assert.Equal(t, tt.expectedExtUsages, cert.ExtKeyUsage)
		})
	}
}
