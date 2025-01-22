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

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sigstore/timestamp-authority/pkg/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetConfigValue(t *testing.T) {
	tests := []struct {
		name      string
		flag      string
		flagValue string
		envVar    string
		envValue  string
		want      string
	}{
		// KMS provider flags
		{
			name:      "get KMS type from flag",
			flag:      "kms-type",
			flagValue: "awskms",
			envVar:    "KMS_TYPE",
			envValue:  "gcpkms",
			want:      "awskms",
		},
		{
			name:      "get AWS region from env",
			flag:      "aws-region",
			flagValue: "",
			envVar:    "AWS_REGION",
			envValue:  "us-west-2",
			want:      "us-west-2",
		},
		{
			name:      "get Azure tenant ID from env",
			flag:      "azure-tenant-id",
			flagValue: "",
			envVar:    "AZURE_TENANT_ID",
			envValue:  "azure-tenant-123",
			want:      "azure-tenant-123",
		},
		{
			name:      "get GCP credentials file from env",
			flag:      "gcp-credentials-file",
			flagValue: "",
			envVar:    "GCP_CREDENTIALS_FILE",
			envValue:  "/path/to/gcp-creds.json",
			want:      "/path/to/gcp-creds.json",
		},
		{
			name:      "get HashiVault token from env",
			flag:      "vault-token",
			flagValue: "",
			envVar:    "VAULT_TOKEN",
			envValue:  "vault-token-123",
			want:      "vault-token-123",
		},
		{
			name:      "get HashiVault address from env",
			flag:      "vault-address",
			flagValue: "",
			envVar:    "VAULT_ADDR",
			envValue:  "http://vault:8200",
			want:      "http://vault:8200",
		},
		// Root certificate flags
		{
			name:      "get root key ID from env",
			flag:      "root-key-id",
			flagValue: "",
			envVar:    "KMS_ROOT_KEY_ID",
			envValue:  "root-key-123",
			want:      "root-key-123",
		},
		// Intermediate certificate flags
		{
			name:      "get intermediate key ID from env",
			flag:      "intermediate-key-id",
			flagValue: "",
			envVar:    "KMS_INTERMEDIATE_KEY_ID",
			envValue:  "intermediate-key-123",
			want:      "intermediate-key-123",
		},
		// Leaf certificate flags
		{
			name:      "get leaf key ID from env",
			flag:      "leaf-key-id",
			flagValue: "",
			envVar:    "KMS_LEAF_KEY_ID",
			envValue:  "leaf-key-123",
			want:      "leaf-key-123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				os.Setenv(tt.envVar, tt.envValue)
				defer os.Unsetenv(tt.envVar)
			}
			viper.Reset()
			viper.BindEnv(tt.flag, tt.envVar)
			if tt.flagValue != "" {
				viper.Set(tt.flag, tt.flagValue)
			}
			got := viper.GetString(tt.flag)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestInitLogger(t *testing.T) {
	log.ConfigureLogger("prod")
	require.NotNil(t, log.Logger)
}

func TestInitLoggerWithDebug(t *testing.T) {
	os.Setenv("DEBUG", "true")
	defer os.Unsetenv("DEBUG")
	log.ConfigureLogger("dev")
	require.NotNil(t, log.Logger)
}

func TestInitLoggerWithInvalidLevel(t *testing.T) {
	os.Setenv("DEBUG", "invalid")
	defer os.Unsetenv("DEBUG")
	log.ConfigureLogger("prod")
	require.NotNil(t, log.Logger)

	os.Setenv("DEBUG", "")
	log.ConfigureLogger("prod")
	require.NotNil(t, log.Logger)
}

func TestRunCreate(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cert-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	rootTemplate := `{
		"subject": {
			"commonName": "Test TSA Root CA"
		},
		"issuer": {
			"commonName": "Test TSA Root CA"
		},
		"notBefore": "2024-01-01T00:00:00Z",
		"notAfter": "2025-01-01T00:00:00Z",
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
		"notBefore": "2024-01-01T00:00:00Z",
		"notAfter": "2025-01-01T00:00:00Z",
		"keyUsage": ["digitalSignature"],
		"extKeyUsage": ["TimeStamping"],
		"basicConstraints": {
			"isCA": false
		}
	}`

	rootTmplPath := filepath.Join(tmpDir, "root-template.json")
	leafTmplPath := filepath.Join(tmpDir, "leaf-template.json")
	err = os.WriteFile(rootTmplPath, []byte(rootTemplate), 0600)
	require.NoError(t, err)
	err = os.WriteFile(leafTmplPath, []byte(leafTemplate), 0600)
	require.NoError(t, err)

	tests := []struct {
		name      string
		args      []string
		envVars   map[string]string
		wantError bool
		errMsg    string
	}{
		{
			name: "missing KMS type",
			args: []string{
				"--aws-region", "us-west-2",
				"--root-key-id", "test-root-key",
				"--leaf-key-id", "test-leaf-key",
				"--root-template", rootTmplPath,
				"--leaf-template", leafTmplPath,
			},
			wantError: true,
			errMsg:    "KMS type cannot be empty",
		},
		{
			name: "invalid KMS type",
			args: []string{
				"--kms-type", "invalid",
				"--aws-region", "us-west-2",
				"--root-key-id", "test-root-key",
				"--leaf-key-id", "test-leaf-key",
				"--root-template", rootTmplPath,
				"--leaf-template", leafTmplPath,
			},
			wantError: true,
			errMsg:    "unsupported KMS type",
		},
		{
			name: "missing root template",
			args: []string{
				"--kms-type", "awskms",
				"--aws-region", "us-west-2",
				"--root-key-id", "alias/test-key",
				"--leaf-key-id", "alias/test-key",
				"--root-template", "nonexistent.json",
				"--leaf-template", leafTmplPath,
			},
			wantError: true,
			errMsg:    "root template error: template not found at nonexistent.json",
		},
		{
			name: "missing leaf template",
			args: []string{
				"--kms-type", "awskms",
				"--aws-region", "us-west-2",
				"--root-key-id", "alias/test-key",
				"--leaf-key-id", "alias/test-key",
				"--root-template", rootTmplPath,
				"--leaf-template", "nonexistent.json",
			},
			wantError: true,
			errMsg:    "leaf template error: template not found at nonexistent.json",
		},
		{
			name: "GCP KMS with credentials file",
			args: []string{
				"--kms-type", "gcpkms",
				"--root-key-id", "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1",
				"--leaf-key-id", "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/leaf-key/cryptoKeyVersions/1",
				"--gcp-credentials-file", "/nonexistent/credentials.json",
				"--root-template", rootTmplPath,
				"--leaf-template", leafTmplPath,
			},
			wantError: true,
			errMsg:    "failed to initialize KMS: credentials file not found",
		},
		{
			name: "Azure KMS without tenant ID",
			args: []string{
				"--kms-type", "azurekms",
				"--root-key-id", "azurekms:name=test-key;vault=test-vault",
				"--leaf-key-id", "azurekms:name=leaf-key;vault=test-vault",
				"--root-template", rootTmplPath,
				"--leaf-template", leafTmplPath,
			},
			wantError: true,
			errMsg:    "tenant-id is required",
		},
		{
			name: "AWS KMS test",
			args: []string{
				"--kms-type", "awskms",
				"--aws-region", "us-west-2",
				"--root-key-id", "alias/test-key",
				"--leaf-key-id", "alias/test-key",
				"--root-template", rootTmplPath,
				"--leaf-template", leafTmplPath,
			},
			wantError: true,
			errMsg:    "error getting root public key: getting public key: operation error KMS: GetPublicKey",
		},
		{
			name: "HashiVault KMS without token",
			args: []string{
				"--kms-type", "hashivault",
				"--root-key-id", "transit/keys/test-key",
				"--leaf-key-id", "transit/keys/leaf-key",
				"--vault-address", "http://vault:8200",
				"--root-template", rootTmplPath,
				"--leaf-template", leafTmplPath,
			},
			wantError: true,
			errMsg:    "token is required for HashiVault KMS",
		},
		{
			name: "HashiVault KMS without address",
			args: []string{
				"--kms-type", "hashivault",
				"--root-key-id", "transit/keys/test-key",
				"--leaf-key-id", "transit/keys/leaf-key",
				"--vault-token", "test-token",
				"--root-template", rootTmplPath,
				"--leaf-template", leafTmplPath,
			},
			wantError: true,
			errMsg:    "address is required for HashiVault KMS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			cmd := &cobra.Command{}
			for i := 0; i < len(tt.args); i += 2 {
				flag := tt.args[i][2:] // Remove "--" prefix
				value := tt.args[i+1]
				viper.Set(flag, value)
			}

			err := runCreate(cmd, nil)
			if tt.wantError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCreateCommand(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cert-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	rootTemplate := `{
		"subject": {
			"commonName": "Test TSA Root CA"
		},
		"issuer": {
			"commonName": "Test TSA Root CA"
		},
		"notBefore": "2024-01-01T00:00:00Z",
		"notAfter": "2025-01-01T00:00:00Z",
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
		"notBefore": "2024-01-01T00:00:00Z",
		"notAfter": "2025-01-01T00:00:00Z",
		"keyUsage": ["digitalSignature"],
		"extKeyUsage": ["TimeStamping"],
		"basicConstraints": {
			"isCA": false
		}
	}`

	rootTmplPath := filepath.Join(tmpDir, "root-template.json")
	leafTmplPath := filepath.Join(tmpDir, "leaf-template.json")
	err = os.WriteFile(rootTmplPath, []byte(rootTemplate), 0600)
	require.NoError(t, err)
	err = os.WriteFile(leafTmplPath, []byte(leafTemplate), 0600)
	require.NoError(t, err)

	tests := []struct {
		name      string
		args      []string
		wantError bool
		errMsg    string
	}{
		{
			name: "missing KMS type",
			args: []string{
				"--aws-region", "us-west-2",
				"--root-key-id", "test-root-key",
				"--leaf-key-id", "test-leaf-key",
				"--root-template", rootTmplPath,
				"--leaf-template", leafTmplPath,
			},
			wantError: true,
			errMsg:    "KMS type cannot be empty",
		},
		{
			name: "invalid KMS type",
			args: []string{
				"--kms-type", "invalid",
				"--aws-region", "us-west-2",
				"--root-key-id", "test-root-key",
				"--leaf-key-id", "test-leaf-key",
				"--root-template", rootTmplPath,
				"--leaf-template", leafTmplPath,
			},
			wantError: true,
			errMsg:    "unsupported KMS type",
		},
		{
			name: "AWS KMS test",
			args: []string{
				"--kms-type", "awskms",
				"--aws-region", "us-west-2",
				"--root-key-id", "alias/test-key",
				"--leaf-key-id", "alias/test-key",
				"--root-template", rootTmplPath,
				"--leaf-template", leafTmplPath,
			},
			wantError: true,
			errMsg:    "error getting root public key: getting public key: operation error KMS: GetPublicKey",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			cmd := &cobra.Command{}
			for i := 0; i < len(tt.args); i += 2 {
				flag := tt.args[i][2:] // Remove "--" prefix
				value := tt.args[i+1]
				viper.Set(flag, value)
			}

			err := runCreate(cmd, nil)
			if tt.wantError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestRootCommand(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantError bool
	}{
		{
			name:      "help flag",
			args:      []string{"--help"},
			wantError: false,
		},
		{
			name:      "unknown flag",
			args:      []string{"--unknown"},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			rootCmd.SetArgs(tt.args)
			err := rootCmd.Execute()
			if tt.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
