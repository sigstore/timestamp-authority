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
		{
			name:      "get root key ID from env",
			flag:      "root-key-id",
			flagValue: "",
			envVar:    "KMS_ROOT_KEY_ID",
			envValue:  "root-key-123",
			want:      "root-key-123",
		},
		{
			name:      "get intermediate key ID from env",
			flag:      "intermediate-key-id",
			flagValue: "",
			envVar:    "KMS_INTERMEDIATE_KEY_ID",
			envValue:  "intermediate-key-123",
			want:      "intermediate-key-123",
		},
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
			"commonName": "Test TSA Root CA"
		},
		"certLife": "8760h",
		"keyUsage": ["digitalSignature"],
		"extKeyUsage": ["TimeStamping"],
		"basicConstraints": {
			"isCA": false
		}
	}`

	intermediateTemplate := `{
		"subject": {
			"commonName": "Test Intermediate CA"
		},
		"notBefore": "2024-01-01T00:00:00Z",
		"notAfter": "2025-01-01T00:00:00Z",
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 0
		}
	}`

	invalidIntermediateTemplate := `{
		"invalid": json
		"missing": comma
	}`

	rootTmplPath := filepath.Join(tmpDir, "root-template.json")
	leafTmplPath := filepath.Join(tmpDir, "leaf-template.json")
	intermediateTmplPath := filepath.Join(tmpDir, "intermediate-template.json")
	invalidIntermediateTmplPath := filepath.Join(tmpDir, "invalid-intermediate-template.json")
	err = os.WriteFile(rootTmplPath, []byte(rootTemplate), 0600)
	require.NoError(t, err)
	err = os.WriteFile(leafTmplPath, []byte(leafTemplate), 0600)
	require.NoError(t, err)
	err = os.WriteFile(intermediateTmplPath, []byte(intermediateTemplate), 0600)
	require.NoError(t, err)
	err = os.WriteFile(invalidIntermediateTmplPath, []byte(invalidIntermediateTemplate), 0600)
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
			errMsg:    "leaf template error: leaf certificate must have a parent",
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
		{
			name: "nonexistent intermediate template",
			args: []string{
				"--kms-type", "awskms",
				"--aws-region", "us-west-2",
				"--root-key-id", "alias/test-key",
				"--leaf-key-id", "alias/test-key",
				"--intermediate-key-id", "alias/test-key",
				"--root-template", rootTmplPath,
				"--leaf-template", leafTmplPath,
				"--intermediate-template", "nonexistent.json",
			},
			wantError: true,
			errMsg:    "intermediate template error: template not found at nonexistent.json",
		},
		{
			name: "invalid intermediate template json",
			args: []string{
				"--kms-type", "awskms",
				"--aws-region", "us-west-2",
				"--root-key-id", "alias/test-key",
				"--leaf-key-id", "alias/test-key",
				"--intermediate-key-id", "alias/test-key",
				"--root-template", rootTmplPath,
				"--leaf-template", leafTmplPath,
				"--intermediate-template", invalidIntermediateTmplPath,
			},
			wantError: true,
			errMsg:    "intermediate template error: invalid template JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			cmd := &cobra.Command{}
			for i := 0; i < len(tt.args); i += 2 {
				flag := tt.args[i][2:]
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
			"commonName": "Test TSA Root CA"
		},
		"certLife": "8760h",
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
			errMsg:    "leaf template error: leaf certificate must have a parent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			cmd := &cobra.Command{}
			for i := 0; i < len(tt.args); i += 2 {
				flag := tt.args[i][2:]
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

func TestEnvironmentVariableHandling(t *testing.T) {
	tests := []struct {
		name        string
		envVars     map[string]string
		args        []string
		wantError   bool
		errorString string
	}{
		{
			name: "AWS KMS from environment",
			envVars: map[string]string{
				"KMS_TYPE":        "awskms",
				"AWS_REGION":      "us-west-2",
				"KMS_ROOT_KEY_ID": "alias/test-root",
				"KMS_LEAF_KEY_ID": "alias/test-leaf",
			},
			args:      []string{"create"},
			wantError: true,
		},
		{
			name: "GCP KMS from environment",
			envVars: map[string]string{
				"KMS_TYPE":             "gcpkms",
				"GCP_CREDENTIALS_FILE": "/path/to/creds.json",
				"KMS_ROOT_KEY_ID":      "projects/test/locations/global/keyRings/test/cryptoKeys/root/cryptoKeyVersions/1",
				"KMS_LEAF_KEY_ID":      "projects/test/locations/global/keyRings/test/cryptoKeys/leaf/cryptoKeyVersions/1",
			},
			args:        []string{"create"},
			wantError:   true,
			errorString: "credentials file not found",
		},
		{
			name: "Azure KMS from environment",
			envVars: map[string]string{
				"KMS_TYPE":        "azurekms",
				"AZURE_TENANT_ID": "test-tenant",
				"KMS_ROOT_KEY_ID": "azurekms:name=test-key;vault=test-vault",
				"KMS_LEAF_KEY_ID": "azurekms:name=test-key;vault=test-vault",
			},
			args:      []string{"create"},
			wantError: true,
		},
		{
			name: "HashiVault KMS from environment",
			envVars: map[string]string{
				"KMS_TYPE":        "hashivault",
				"VAULT_TOKEN":     "test-token",
				"VAULT_ADDR":      "http://vault:8200",
				"KMS_ROOT_KEY_ID": "transit/keys/test-root",
				"KMS_LEAF_KEY_ID": "transit/keys/test-leaf",
			},
			args:      []string{"create"},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldEnv := map[string]string{}
			for k := range tt.envVars {
				if v, ok := os.LookupEnv(k); ok {
					oldEnv[k] = v
				}
			}

			for k, v := range tt.envVars {
				os.Setenv(k, v)
			}

			viper.Reset()

			viper.BindEnv("kms-type", "KMS_TYPE")
			viper.BindEnv("aws-region", "AWS_REGION")
			viper.BindEnv("azure-tenant-id", "AZURE_TENANT_ID")
			viper.BindEnv("gcp-credentials-file", "GCP_CREDENTIALS_FILE")
			viper.BindEnv("vault-token", "VAULT_TOKEN")
			viper.BindEnv("vault-address", "VAULT_ADDR")
			viper.BindEnv("root-key-id", "KMS_ROOT_KEY_ID")
			viper.BindEnv("leaf-key-id", "KMS_LEAF_KEY_ID")

			defer func() {
				for k := range tt.envVars {
					if v, ok := oldEnv[k]; ok {
						os.Setenv(k, v)
					} else {
						os.Unsetenv(k)
					}
				}
			}()

			cmd := &cobra.Command{
				Use:  "test",
				RunE: runCreate,
			}

			cmd.Flags().String("kms-type", "", "KMS type")
			cmd.Flags().String("aws-region", "", "AWS region")
			cmd.Flags().String("azure-tenant-id", "", "Azure tenant ID")
			cmd.Flags().String("gcp-credentials-file", "", "GCP credentials file")
			cmd.Flags().String("vault-token", "", "HashiVault token")
			cmd.Flags().String("vault-address", "", "HashiVault address")
			cmd.Flags().String("root-key-id", "", "Root key ID")
			cmd.Flags().String("leaf-key-id", "", "Leaf key ID")
			cmd.Flags().String("root-template", "templates/root-template.json", "Root template")
			cmd.Flags().String("leaf-template", "templates/leaf-template.json", "Leaf template")

			viper.BindPFlag("kms-type", cmd.Flags().Lookup("kms-type"))
			viper.BindPFlag("aws-region", cmd.Flags().Lookup("aws-region"))
			viper.BindPFlag("azure-tenant-id", cmd.Flags().Lookup("azure-tenant-id"))
			viper.BindPFlag("gcp-credentials-file", cmd.Flags().Lookup("gcp-credentials-file"))
			viper.BindPFlag("vault-token", cmd.Flags().Lookup("vault-token"))
			viper.BindPFlag("vault-address", cmd.Flags().Lookup("vault-address"))
			viper.BindPFlag("root-key-id", cmd.Flags().Lookup("root-key-id"))
			viper.BindPFlag("leaf-key-id", cmd.Flags().Lookup("leaf-key-id"))
			viper.BindPFlag("root-template", cmd.Flags().Lookup("root-template"))
			viper.BindPFlag("leaf-template", cmd.Flags().Lookup("leaf-template"))

			cmd.SetArgs(tt.args)
			err := cmd.Execute()

			if tt.wantError {
				require.Error(t, err)
				if tt.errorString != "" {
					assert.Contains(t, err.Error(), tt.errorString)
				}
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, tt.envVars["KMS_TYPE"], viper.GetString("kms-type"))
			assert.Equal(t, tt.envVars["KMS_ROOT_KEY_ID"], viper.GetString("root-key-id"))
			assert.Equal(t, tt.envVars["KMS_LEAF_KEY_ID"], viper.GetString("leaf-key-id"))
		})
	}
}

func TestKMSProviderConfigurationValidation(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantError   bool
		errorString string
	}{
		{
			name: "AWS KMS invalid key format",
			args: []string{
				"create",
				"--kms-type", "awskms",
				"--aws-region", "us-west-2",
				"--root-key-id", "invalid-format",
				"--leaf-key-id", "invalid-format",
			},
			wantError:   true,
			errorString: "must start with 'arn:aws:kms:' or 'alias/'",
		},
		{
			name: "GCP KMS missing key version",
			args: []string{
				"create",
				"--kms-type", "gcpkms",
				"--root-key-id", "projects/test/locations/global/keyRings/test/cryptoKeys/test",
				"--leaf-key-id", "projects/test/locations/global/keyRings/test/cryptoKeys/test",
			},
			wantError:   true,
			errorString: "must contain '/cryptoKeyVersions/'",
		},
		{
			name: "Azure KMS invalid key format",
			args: []string{
				"create",
				"--kms-type", "azurekms",
				"--azure-tenant-id", "test-tenant",
				"--root-key-id", "invalid-format",
				"--leaf-key-id", "invalid-format",
			},
			wantError:   true,
			errorString: "must start with 'azurekms:name='",
		},
		{
			name: "HashiVault KMS invalid key path",
			args: []string{
				"create",
				"--kms-type", "hashivault",
				"--vault-token", "test-token",
				"--vault-address", "http://vault:8200",
				"--root-key-id", "invalid/path",
				"--leaf-key-id", "invalid/path",
			},
			wantError:   true,
			errorString: "must be in format: transit/keys/keyname",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			cmd := &cobra.Command{
				Use:  "test",
				RunE: runCreate,
			}

			cmd.Flags().String("kms-type", "", "KMS type")
			cmd.Flags().String("aws-region", "", "AWS region")
			cmd.Flags().String("azure-tenant-id", "", "Azure tenant ID")
			cmd.Flags().String("vault-token", "", "HashiVault token")
			cmd.Flags().String("vault-address", "", "HashiVault address")
			cmd.Flags().String("root-key-id", "", "Root key ID")
			cmd.Flags().String("leaf-key-id", "", "Leaf key ID")
			cmd.Flags().String("root-template", "templates/root-template.json", "Root template")
			cmd.Flags().String("leaf-template", "templates/leaf-template.json", "Leaf template")

			viper.BindPFlag("kms-type", cmd.Flags().Lookup("kms-type"))
			viper.BindPFlag("aws-region", cmd.Flags().Lookup("aws-region"))
			viper.BindPFlag("azure-tenant-id", cmd.Flags().Lookup("azure-tenant-id"))
			viper.BindPFlag("vault-token", cmd.Flags().Lookup("vault-token"))
			viper.BindPFlag("vault-address", cmd.Flags().Lookup("vault-address"))
			viper.BindPFlag("root-key-id", cmd.Flags().Lookup("root-key-id"))
			viper.BindPFlag("leaf-key-id", cmd.Flags().Lookup("leaf-key-id"))
			viper.BindPFlag("root-template", cmd.Flags().Lookup("root-template"))
			viper.BindPFlag("leaf-template", cmd.Flags().Lookup("leaf-template"))

			cmd.SetArgs(tt.args)
			err := cmd.Execute()

			if tt.wantError {
				require.Error(t, err)
				if tt.errorString != "" {
					assert.Contains(t, err.Error(), tt.errorString)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}
