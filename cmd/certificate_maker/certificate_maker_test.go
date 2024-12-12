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

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetConfigValue(t *testing.T) {
	tests := []struct {
		name      string
		flagValue string
		envVar    string
		envValue  string
		want      string
	}{
		{
			name:      "flag value takes precedence",
			flagValue: "flag-value",
			envVar:    "TEST_ENV",
			envValue:  "env-value",
			want:      "flag-value",
		},
		{
			name:      "env value used when flag empty",
			flagValue: "",
			envVar:    "TEST_ENV",
			envValue:  "env-value",
			want:      "env-value",
		},
		{
			name:      "empty when both unset",
			flagValue: "",
			envVar:    "TEST_ENV",
			envValue:  "",
			want:      "",
		},
		{
			name:      "GCP credentials file from env",
			flagValue: "",
			envVar:    "GCP_CREDENTIALS_FILE",
			envValue:  "/path/to/creds.json",
			want:      "/path/to/creds.json",
		},
		{
			name:      "Azure tenant ID from env",
			flagValue: "",
			envVar:    "AZURE_TENANT_ID",
			envValue:  "tenant-123",
			want:      "tenant-123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				os.Setenv(tt.envVar, tt.envValue)
				defer os.Unsetenv(tt.envVar)
			}
			got := getConfigValue(tt.flagValue, tt.envVar)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestInitLogger(t *testing.T) {
	logger := initLogger()
	require.NotNil(t, logger)
}

func TestRunCreate(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cert-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create test template files
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
				"--kms-region", "us-west-2",
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
				"--kms-region", "us-west-2",
				"--root-key-id", "arn:aws:kms:us-west-2:123456789012:key/test-key",
				"--leaf-key-id", "arn:aws:kms:us-west-2:123456789012:key/test-key",
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
				"--kms-region", "us-west-2",
				"--root-key-id", "arn:aws:kms:us-west-2:123456789012:key/test-key",
				"--leaf-key-id", "arn:aws:kms:us-west-2:123456789012:key/test-key",
				"--root-template", "nonexistent.json",
				"--leaf-template", leafTmplPath,
			},
			wantError: true,
			errMsg:    "template not found",
		},
		{
			name: "missing leaf template",
			args: []string{
				"--kms-type", "awskms",
				"--kms-region", "us-west-2",
				"--root-key-id", "arn:aws:kms:us-west-2:123456789012:key/test-key",
				"--leaf-key-id", "arn:aws:kms:us-west-2:123456789012:key/test-key",
				"--root-template", rootTmplPath,
				"--leaf-template", "nonexistent.json",
			},
			wantError: true,
			errMsg:    "template not found",
		},
		{
			name: "GCP KMS with credentials file",
			args: []string{
				"--kms-type", "gcpkms",
				"--root-key-id", "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1",
				"--leaf-key-id", "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/leaf-key/cryptoKeyVersions/1",
				"--gcpkms-credentials-file", "/nonexistent/credentials.json",
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables
			for k, v := range tt.envVars {
				os.Setenv(k, v)
				defer os.Unsetenv(k)
			}

			cmd := &cobra.Command{
				Use:  "test",
				RunE: runCreate,
			}

			// Add all flags that runCreate expects
			cmd.Flags().StringVar(&kmsType, "kms-type", "", "KMS provider type (awskms, gcpkms, azurekms)")
			cmd.Flags().StringVar(&kmsRegion, "kms-region", "", "KMS region")
			cmd.Flags().StringVar(&kmsKeyID, "kms-key-id", "", "KMS key identifier")
			cmd.Flags().StringVar(&kmsTenantID, "azure-tenant-id", "", "Azure KMS tenant ID")
			cmd.Flags().StringVar(&kmsCredsFile, "gcpkms-credentials-file", "", "Path to credentials file for GCP KMS")
			cmd.Flags().StringVar(&rootKeyID, "root-key-id", "", "KMS key identifier for root certificate")
			cmd.Flags().StringVar(&leafKeyID, "leaf-key-id", "", "KMS key identifier for leaf certificate")
			cmd.Flags().StringVar(&rootTemplatePath, "root-template", "", "Path to root certificate template")
			cmd.Flags().StringVar(&leafTemplatePath, "leaf-template", "", "Path to leaf certificate template")
			cmd.Flags().StringVar(&rootCertPath, "root-cert", "root.pem", "Output path for root certificate")
			cmd.Flags().StringVar(&leafCertPath, "leaf-cert", "leaf.pem", "Output path for leaf certificate")
			cmd.Flags().StringVar(&intermediateKeyID, "intermediate-key-id", "", "KMS key identifier for intermediate certificate")
			cmd.Flags().StringVar(&intermediateTemplate, "intermediate-template", "", "Path to intermediate certificate template")
			cmd.Flags().StringVar(&intermediateCert, "intermediate-cert", "intermediate.pem", "Output path for intermediate certificate")

			cmd.SetArgs(tt.args)
			err := cmd.Execute()

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
	// Create a test command
	cmd := &cobra.Command{
		Use: "test",
		RunE: func(_ *cobra.Command, _ []string) error {
			return nil
		},
	}

	// Add flags
	cmd.Flags().StringVar(&kmsType, "kms-type", "", "KMS type")
	cmd.Flags().StringVar(&kmsRegion, "kms-region", "", "KMS region")
	cmd.Flags().StringVar(&rootKeyID, "root-key-id", "", "Root key ID")
	cmd.Flags().StringVar(&leafKeyID, "leaf-key-id", "", "Leaf key ID")

	// Test missing required flags
	err := cmd.Execute()
	require.NoError(t, err) // No required flags set yet

	// Test flag parsing
	err = cmd.ParseFlags([]string{
		"--kms-type", "awskms",
		"--kms-region", "us-west-2",
		"--root-key-id", "arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab",
		"--leaf-key-id", "arn:aws:kms:us-west-2:123456789012:key/9876fedc-ba98-7654-3210-fedcba987654",
	})
	require.NoError(t, err)

	// Verify flag values
	assert.Equal(t, "awskms", kmsType)
	assert.Equal(t, "us-west-2", kmsRegion)
	assert.Equal(t, "arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab", rootKeyID)
	assert.Equal(t, "arn:aws:kms:us-west-2:123456789012:key/9876fedc-ba98-7654-3210-fedcba987654", leafKeyID)
}

func TestRootCommand(t *testing.T) {
	// Test help output
	rootCmd.SetArgs([]string{"--help"})
	err := rootCmd.Execute()
	require.NoError(t, err)

	// Test unknown command
	rootCmd.SetArgs([]string{"unknown"})
	err = rootCmd.Execute()
	require.Error(t, err)
}
