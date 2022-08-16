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
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"

	"github.com/pkg/errors"
	"github.com/spf13/viper"

	"github.com/sigstore/timestamp-authority/pkg/log"
	pki "github.com/sigstore/timestamp-authority/pkg/pki/x509"
	"github.com/sigstore/timestamp-authority/pkg/signer"
)

type API struct {
	tsaSigner    crypto.Signer       // the signer to use for timestamping
	certChain    []*x509.Certificate // timestamping cert chain
	certChainPem string              // PEM encoded timestamping cert chain
}

func NewAPI() (*API, error) {
	ctx := context.Background()

	// TODO(hayden): Revamp
	// * Load key from disk with Tink (Requires KMS decryption key)
	// * Load certificate chain from config, without extra base64 encoding
	rekorSigner, err := signer.New(ctx, viper.GetString("timestamp_server.signer"))
	if err != nil {
		return nil, errors.Wrap(err, "getting new signer")
	}

	// timestamping authority setup
	// Use an in-memory key for timestamping
	tsaSigner, err := signer.NewCryptoSigner(ctx, viper.GetString("timestamp_server.timestamp_signer"))
	if err != nil {
		return nil, errors.Wrap(err, "getting new tsa signer")
	}

	var certChain []*x509.Certificate
	b64CertChainStr := viper.GetString("timestamp_server.timestamp_chain")
	if b64CertChainStr != "" {
		certChainStr, err := base64.StdEncoding.DecodeString(b64CertChainStr)
		if err != nil {
			return nil, errors.Wrap(err, "decoding timestamping cert")
		}
		if certChain, err = pki.ParseTimestampCertChain([]byte(certChainStr)); err != nil {
			return nil, errors.Wrap(err, "parsing timestamp cert chain")
		}
	}
	// TODO: Verify certificate chain for non-in-memory

	// Generate a tsa certificate from the rekor signer and provided certificate chain
	certChain, err = signer.NewTimestampingCertWithChain(ctx, tsaSigner.Public(), rekorSigner, certChain)
	if err != nil {
		return nil, errors.Wrap(err, "generating timestamping cert chain")
	}
	certChainPem, err := pki.CertChainToPEM(certChain)
	if err != nil {
		return nil, errors.Wrap(err, "timestamping cert chain")
	}

	return &API{
		tsaSigner:    tsaSigner,
		certChain:    certChain,
		certChainPem: string(certChainPem),
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
