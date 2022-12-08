//
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

package api

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/spf13/viper"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/timestamp-authority/pkg/log"
	"github.com/sigstore/timestamp-authority/pkg/signer"
	tsx509 "github.com/sigstore/timestamp-authority/pkg/x509"
)

type API struct {
	tsaSigner    crypto.Signer       // the signer to use for timestamping
	certChain    []*x509.Certificate // timestamping cert chain
	certChainPem string              // PEM encoded timestamping cert chain
}

func NewAPI() (*API, error) {
	ctx := context.Background()

	tsaSigner, err := signer.NewCryptoSigner(ctx, viper.GetString("timestamp-signer"),
		viper.GetString("kms-key-resource"),
		viper.GetString("tink-key-resource"), viper.GetString("tink-keyset-path"),
		viper.GetString("tink-hcvault-token"),
		viper.GetString("file-signer-key-path"), viper.GetString("file-signer-passwd"))
	if err != nil {
		return nil, errors.Wrap(err, "getting new tsa signer")
	}

	var certChain []*x509.Certificate

	// KMS, Tink and File signers require a provided certificate chain
	if viper.GetString("timestamp-signer") != signer.MemoryScheme {
		certChainPath := viper.GetString("certificate-chain-path")
		data, err := os.ReadFile(filepath.Clean(certChainPath))
		if err != nil {
			return nil, err
		}
		certChain, err = cryptoutils.LoadCertificatesFromPEM(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		if err := tsx509.VerifyCertChain(certChain, tsaSigner); err != nil {
			return nil, err
		}
	} else {
		// Generate an in-memory TSA certificate chain
		certChain, err = signer.NewTimestampingCertWithChain(tsaSigner)
		if err != nil {
			return nil, errors.Wrap(err, "generating timestamping cert chain")
		}
	}

	certChainPEM, err := cryptoutils.MarshalCertificatesToPEM(certChain)
	if err != nil {
		return nil, fmt.Errorf("marshal certificates to PEM: %w", err)
	}

	return &API{
		tsaSigner:    tsaSigner,
		certChain:    certChain,
		certChainPem: string(certChainPEM),
	}, nil
}

var (
	api *API
)

func ConfigureAPI() {
	var err error

	api, err = NewAPI()
	if err != nil {
		log.Logger.Panic(err)
	}
}
