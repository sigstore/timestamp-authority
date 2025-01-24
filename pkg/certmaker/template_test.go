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

// Package certmaker provides template parsing and certificate generation functionality
// for creating X.509 certificates from JSON templates per RFC3161 standards.
package certmaker

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTemplate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	notAfter := time.Now().Add(time.Hour * 24)

	testRootTemplate := `{
		"subject": {
			"commonName": "Test Root CA"
		},
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 1
		}
	}`

	testLeafTemplate := `{
		"subject": {
			"commonName": "Test Leaf CA"
		},
		"keyUsage": ["digitalSignature"],
		"basicConstraints": {
			"isCA": false
		}
	}`

	tests := []struct {
		name       string
		input      interface{}
		parent     *x509.Certificate
		notAfter   time.Time
		publicKey  crypto.PublicKey
		commonName string
		wantCN     string
		wantError  string
	}{
		{
			name:       "valid_root_template_with_provided_cn",
			input:      testRootTemplate,
			parent:     nil,
			notAfter:   notAfter,
			publicKey:  key.Public(),
			commonName: "Test Root TSA",
			wantCN:     "Test Root TSA",
		},
		{
			name:       "valid_root_template_with_template_cn",
			input:      testRootTemplate,
			parent:     nil,
			notAfter:   notAfter,
			publicKey:  key.Public(),
			commonName: "",
			wantCN:     "Test Root CA",
		},
		{
			name:       "valid_leaf_template_with_provided_cn",
			input:      testLeafTemplate,
			parent:     &x509.Certificate{},
			notAfter:   notAfter,
			publicKey:  key.Public(),
			commonName: "Test TSA",
			wantCN:     "Test TSA",
		},
		{
			name:       "valid_leaf_template_with_template_cn",
			input:      testLeafTemplate,
			parent:     &x509.Certificate{},
			notAfter:   notAfter,
			publicKey:  key.Public(),
			commonName: "",
			wantCN:     "Test Leaf CA",
		},
		{
			name:       "invalid_template",
			input:      "{ invalid json",
			parent:     nil,
			notAfter:   notAfter,
			publicKey:  key.Public(),
			commonName: "Test TSA",
			wantError:  "error parsing template",
		},
		{
			name:       "invalid_input_type",
			input:      123,
			parent:     nil,
			notAfter:   notAfter,
			publicKey:  key.Public(),
			commonName: "Test TSA",
			wantError:  "input must be either a template string or template content",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := ParseTemplate(tt.input, tt.parent, tt.notAfter, tt.publicKey, tt.commonName)
			if tt.wantError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			} else {
				require.NoError(t, err)
				require.NotNil(t, cert)
				assert.Equal(t, tt.wantCN, cert.Subject.CommonName)
				assert.Equal(t, tt.publicKey, cert.PublicKey)
				assert.Equal(t, tt.notAfter, cert.NotAfter)
			}
		})
	}
}

func TestValidateTemplate(t *testing.T) {
	tmpDir := t.TempDir()

	validTemplate := `{
		"subject": {
			"commonName": "Test CA"
		},
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 1
		}
	}`

	invalidJSON := `{
		"subject": {
			"commonName": "Test CA"
		},
		"keyUsage": ["invalidUsage"],
		"basicConstraints": {
			"isCA": "not a boolean",
			"maxPathLen": 1
		}
	}`

	validPath := filepath.Join(tmpDir, "valid.json")
	invalidJSONPath := filepath.Join(tmpDir, "invalid.json")
	nonexistentPath := filepath.Join(tmpDir, "nonexistent.json")

	err := os.WriteFile(validPath, []byte(validTemplate), 0600)
	require.NoError(t, err)
	err = os.WriteFile(invalidJSONPath, []byte(invalidJSON), 0600)
	require.NoError(t, err)

	tests := []struct {
		name     string
		filename string
		parent   *x509.Certificate
		certType string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "valid_root_template",
			filename: validPath,
			parent:   nil,
			certType: "root",
			wantErr:  false,
		},
		{
			name:     "valid_intermediate_template",
			filename: validPath,
			parent:   &x509.Certificate{},
			certType: "intermediate",
			wantErr:  false,
		},
		{
			name:     "valid_leaf_template",
			filename: validPath,
			parent:   &x509.Certificate{},
			certType: "leaf",
			wantErr:  false,
		},
		{
			name:     "invalid_root_with_parent",
			filename: validPath,
			parent:   &x509.Certificate{},
			certType: "root",
			wantErr:  true,
			errMsg:   "root certificate cannot have a parent",
		},
		{
			name:     "invalid_intermediate_no_parent",
			filename: validPath,
			parent:   nil,
			certType: "intermediate",
			wantErr:  true,
			errMsg:   "intermediate certificate must have a parent",
		},
		{
			name:     "invalid_leaf_no_parent",
			filename: validPath,
			parent:   nil,
			certType: "leaf",
			wantErr:  true,
			errMsg:   "leaf certificate must have a parent",
		},
		{
			name:     "invalid_cert_type",
			filename: validPath,
			parent:   nil,
			certType: "invalid",
			wantErr:  true,
			errMsg:   "invalid certificate type",
		},
		{
			name:     "nonexistent_file",
			filename: nonexistentPath,
			parent:   nil,
			certType: "root",
			wantErr:  true,
			errMsg:   "template not found at",
		},
		{
			name:     "invalid_json",
			filename: invalidJSONPath,
			parent:   nil,
			certType: "root",
			wantErr:  true,
			errMsg:   "invalid template JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTemplate(tt.filename, tt.parent, tt.certType)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDeterminePublicKeyAlgorithm(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name      string
		publicKey crypto.PublicKey
		want      x509.PublicKeyAlgorithm
	}{
		{
			name:      "ECDSA key",
			publicKey: ecKey.Public(),
			want:      x509.ECDSA,
		},
		{
			name:      "RSA key",
			publicKey: rsaKey.Public(),
			want:      x509.RSA,
		},
		{
			name:      "Ed25519 key",
			publicKey: ed25519Key,
			want:      3,
		},
		{
			name:      "Unknown key type",
			publicKey: struct{}{},
			want:      x509.ECDSA,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := determinePublicKeyAlgorithm(tt.publicKey)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetDefaultTemplate(t *testing.T) {
	tests := []struct {
		name      string
		certType  string
		wantError string
		contains  string
	}{
		{
			name:     "root_template",
			certType: "root",
			contains: "certSign",
		},
		{
			name:     "intermediate_template",
			certType: "intermediate",
			contains: "certSign",
		},
		{
			name:     "leaf_template",
			certType: "leaf",
			contains: "oid:1.3.6.1.5.5.7.3.8", // TimeStamping OID
		},
		{
			name:      "invalid_type",
			certType:  "invalid",
			wantError: "invalid certificate type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template, err := GetDefaultTemplate(tt.certType)
			if tt.wantError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			} else {
				require.NoError(t, err)
				assert.Contains(t, template, tt.contains)
			}
		})
	}
}
