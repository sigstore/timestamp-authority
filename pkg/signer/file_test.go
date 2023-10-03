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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"go.step.sm/crypto/pemutil"
)

func TestNewFileSigner(t *testing.T) {
	td := t.TempDir()

	password := "password1!"

	_, ed25519Key, _ := ed25519.GenerateKey(rand.Reader)
	pemED25519, _ := pemutil.Serialize(ed25519Key, pemutil.WithPassword([]byte(password)))
	ed25519KeyFile := filepath.Join(td, "ed25519-key.pem")
	if err := os.WriteFile(ed25519KeyFile, pem.EncodeToMemory(pemED25519), 0644); err != nil {
		t.Fatal(err)
	}

	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pemECDSA, _ := pemutil.Serialize(ecdsaKey, pemutil.WithPassword([]byte(password)))
	ecdsaKeyFile := filepath.Join(td, "ecdsa-key.pem")
	if err := os.WriteFile(ecdsaKeyFile, pem.EncodeToMemory(pemECDSA), 0644); err != nil {
		t.Fatal(err)
	}

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 4096)
	pemRSA, _ := pemutil.Serialize(rsaKey, pemutil.WithPassword([]byte(password)))
	rsaKeyFile := filepath.Join(td, "rsa-key.pem")
	if err := os.WriteFile(rsaKeyFile, pem.EncodeToMemory(pemRSA), 0644); err != nil {
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
			keyPass: password,
			wantErr: false,
		},
		{
			name:    "valid RSA",
			keyPath: rsaKeyFile,
			keyPass: password,
			wantErr: false,
		},
		{
			name:    "valid ed25519",
			keyPath: ed25519KeyFile,
			keyPass: password,
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
			_, err := NewFileSigner(tc.keyPath, tc.keyPass, crypto.SHA256)
			if tc.wantErr != (err != nil) {
				t.Errorf("NewFileSigner() expected %t, got err %s", tc.wantErr, err)
			}
		})
	}
}
