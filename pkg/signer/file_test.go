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
	"os"
	"path/filepath"
	"testing"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func TestNewFileSigner(t *testing.T) {
	td := t.TempDir()

	password := "password1!"

	_, ed25519Key, _ := ed25519.GenerateKey(rand.Reader)
	derED25519, err := cryptoutils.MarshalPrivateKeyToEncryptedDER(ed25519Key, cryptoutils.StaticPasswordFunc([]byte(password)))
	if err != nil {
		t.Fatal(err)
	}
	pemED25519 := cryptoutils.PEMEncode(cryptoutils.EncryptedSigstorePrivateKeyPEMType, derED25519)
	ed25519KeyFile := filepath.Join(td, "ed25519-key.pem")
	if err := os.WriteFile(ed25519KeyFile, pemED25519, 0644); err != nil {
		t.Fatal(err)
	}

	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	derECDSA, err := cryptoutils.MarshalPrivateKeyToEncryptedDER(ecdsaKey, cryptoutils.StaticPasswordFunc([]byte(password)))
	if err != nil {
		t.Fatal(err)
	}
	pemECDSA := cryptoutils.PEMEncode(cryptoutils.EncryptedSigstorePrivateKeyPEMType, derECDSA)
	ecdsaKeyFile := filepath.Join(td, "ecdsa-key.pem")
	if err := os.WriteFile(ecdsaKeyFile, pemECDSA, 0644); err != nil {
		t.Fatal(err)
	}

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 4096)
	derRSA, err := cryptoutils.MarshalPrivateKeyToEncryptedDER(rsaKey, cryptoutils.StaticPasswordFunc([]byte(password)))
	if err != nil {
		t.Fatal(err)
	}
	pemRSA := cryptoutils.PEMEncode(cryptoutils.EncryptedSigstorePrivateKeyPEMType, derRSA)
	rsaKeyFile := filepath.Join(td, "rsa-key.pem")
	if err := os.WriteFile(rsaKeyFile, pemRSA, 0644); err != nil {
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
