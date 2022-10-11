// Copyright 2022 The Sigstore Authors.
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

package signer

import (
	"os"
	"path/filepath"
	"testing"
)

// openssl ecparam -genkey -name secp256r1 | openssl ec -aes256 -out privatekey.pem
const testECDSAKey = `
-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,4969270CE089BA21CF1321071A1E4215

0vdL+mB/ZK71LZoPiGIALhAAfjutNCcLXQSgLBv1ICG+O5bE4VHIFmkxLMND7prM
tplhZuys26J/xuy5YztW1d1T/9CuK2qtGG97gTs7NiPlHGtDJpA5wvQhuarna1qm
JNF/Voi3fIbL52Nq/Ze5GqDyjTyYNLz8eovJQC9Eq7Q=
-----END EC PRIVATE KEY-----`
const testECDSAPass = "password1"

// openssl genrsa -aes256 -passout pass:password1 4096
const testRSAKey = `
openssl genrsa -aes256 -passout pass:password1 4096
-----BEGIN ENCRYPTED PRIVATE KEY-----
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
-----END ENCRYPTED PRIVATE KEY-----`
const testRSAPass = "password1"

func TestFile(t *testing.T) {
	td := t.TempDir()

	ecdsaKeyFile := filepath.Join(td, "ecdsa-key.pem")
	if err := os.WriteFile(ecdsaKeyFile, []byte(testECDSAKey), 0644); err != nil {
		t.Fatal(err)
	}
	rsaKeyFile := filepath.Join(td, "rsa-key.pem")
	if err := os.WriteFile(rsaKeyFile, []byte(testRSAKey), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		keyPath string
		keyPass string
		wantErr bool
	}{
		{
			name:    "valid ECDSA",
			keyPath: ecdsaKeyFile,
			keyPass: testECDSAPass,
			wantErr: false,
		},
		{
			name:    "valid RSA",
			keyPath: rsaKeyFile,
			keyPass: testRSAPass,
			wantErr: false,
		},
		{
			name:    "invalid password",
			keyPath: ecdsaKeyFile,
			keyPass: "123",
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc := tc
			_, err := NewFileSigner(tc.keyPath, tc.keyPass)
			if tc.wantErr != (err != nil) {
				t.Errorf("NewFileSigner() expected %t, got err %s", tc.wantErr, err)
			}
		})
	}
}
