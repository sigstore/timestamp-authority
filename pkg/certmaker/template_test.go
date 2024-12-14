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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
		content   string
		parent    *x509.Certificate
		wantError string
	}{
		{
			name: "valid template",
			content: `{
                "subject": {
                    "commonName": "Test TSA"
                },
                "issuer": {
                    "commonName": "Test TSA"
                },
                "keyUsage": [
                    "digitalSignature"
                ],
                "basicConstraints": {
                    "isCA": false
                },
                "extensions": [
                    {
                        "id": "2.5.29.37",
                        "critical": true,
                        "value": "MCQwIgYDVR0lBBswGQYIKwYBBQUHAwgGDSsGAQQBgjcUAgICAf8="
                    }
                ],
                "notBefore": "2024-01-01T00:00:00Z",
                "notAfter": "2025-01-01T00:00:00Z"
            }`,
			parent: parent,
		},
		{
			name: "missing required fields",
			content: `{
                "issuer": {"commonName": "Test TSA"},
                "notBefore": "2024-01-01T00:00:00Z",
                "notAfter": "2025-01-01T00:00:00Z"
            }`,
			wantError: "subject.commonName cannot be empty",
		},
		{
			name: "invalid time format",
			content: `{
                "subject": {"commonName": "Test TSA"},
                "issuer": {"commonName": "Test TSA"},
                "notBefore": "invalid",
                "notAfter": "2025-01-01T00:00:00Z"
            }`,
			wantError: "invalid notBefore time format",
		},
		{
			name: "missing digital signature usage",
			content: `{
                "subject": {"commonName": "Test TSA"},
                "issuer": {"commonName": "Test TSA"},
                "notBefore": "2024-01-01T00:00:00Z",
                "notAfter": "2025-01-01T00:00:00Z",
                "keyUsage": ["certSign"],
                "basicConstraints": {"isCA": false}
            }`,
			wantError: "timestamp authority certificate must have digitalSignature key usage",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile := filepath.Join(tmpDir, "template.json")
			err := os.WriteFile(tmpFile, []byte(tt.content), 0600)
			if err != nil {
				t.Fatalf("Failed to write template file: %v", err)
			}

			cert, err := ParseTemplate(tmpFile, tt.parent)
			if tt.wantError != "" {
				if err == nil {
					t.Error("Expected error but got none")
				} else if !strings.Contains(err.Error(), tt.wantError) {
					t.Errorf("Expected error containing %q, got %q", tt.wantError, err.Error())
				}
				if cert != nil {
					t.Error("Expected nil certificate when error occurs")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if cert == nil {
					t.Error("Expected non-nil certificate")
				}
			}
		})
	}
}

func TestValidateTemplate(t *testing.T) {
	parent := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "Parent CA",
		},
	}

	tests := []struct {
		name      string
		tmpl      *CertificateTemplate
		parent    *x509.Certificate
		wantError string
	}{
		{
			name: "valid TSA template",
			tmpl: &CertificateTemplate{
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
				NotBefore: "2024-01-01T00:00:00Z",
				NotAfter:  "2025-01-01T00:00:00Z",
				KeyUsage:  []string{"digitalSignature"},
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
			parent: parent,
		},
		{
			name: "empty notBefore time",
			tmpl: &CertificateTemplate{
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
				NotAfter: "2025-01-01T00:00:00Z",
				KeyUsage: []string{"digitalSignature"},
			},
			wantError: "notBefore time must be specified",
		},
		{
			name: "empty notAfter time",
			tmpl: &CertificateTemplate{
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
				NotBefore: "2024-01-01T00:00:00Z",
				KeyUsage:  []string{"digitalSignature"},
			},
			wantError: "notAfter time must be specified",
		},
		{
			name: "invalid notBefore format",
			tmpl: &CertificateTemplate{
				Subject: struct {
					Country            []string `json:"country,omitempty"`
					Organization       []string `json:"organization,omitempty"`
					OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
					CommonName         string   `json:"commonName"`
				}{
					CommonName: "Test TSA",
				},
				NotBefore: "invalid",
				NotAfter:  "2025-01-01T00:00:00Z",
				KeyUsage:  []string{"digitalSignature"},
			},
			wantError: "invalid notBefore time format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTemplate(tt.tmpl, tt.parent)
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
