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
//

package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	privateca "cloud.google.com/go/security/privateca/apiv1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	privatecapb "google.golang.org/genproto/googleapis/cloud/security/privateca/v1"
	"google.golang.org/protobuf/types/known/durationpb"

	// Register the provider-specific plugins
	"github.com/sigstore/sigstore/pkg/signature/kms"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/aws"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/azure"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/gcp"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/hashivault"
)

/*
To run:
go run cmd/fetch_ca_cert/fetch_ca_cert.go \
  --intermediate-kms-resource="gcpkms://projects/<project>/locations/<region>/keyRings/<key-ring>/cryptoKeys/<key>/versions/1" \
  --leaf-kms-resource="gcpkms://projects/<project>/locations/<region>/keyRings/<leaf-key-ring>/cryptoKeys/<key>/versions/1" \
  --gcp-ca-parent="projects/<project>/locations/<region>/caPools/<ca-pool>" \
  --output="chain.crt.pem"

You must have the permissions to read the KMS keys, and create a certificate in the CA pool.
*/

var (
	gcpCaParent        = flag.String("gcp-ca-parent", "", "Resource path to GCP CA Service CA")
	intermediateKMSKey = flag.String("intermediate-kms-resource", "", "Resource path to the KMS key for the intermediate CA, starting with gcpkms://, awskms://, azurekms:// or hashivault://")
	leafKMSKey         = flag.String("leaf-kms-resource", "", "Resource path to the KMS key for the leaf, starting with gcpkms://, awskms://, azurekms:// or hashivault://")
	outputPath         = flag.String("output", "", "Path to the output file")
)

func fetchCACertificate(ctx context.Context, parent, intermediateKMSKey, leafKMSKey string, client *privateca.CertificateAuthorityClient) ([]*x509.Certificate, error) {
	intermediateKMSSigner, err := kms.Get(ctx, intermediateKMSKey, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	intermediateSigner, _, err := intermediateKMSSigner.CryptoSigner(ctx, func(err error) {})
	if err != nil {
		return nil, err
	}

	pemPubKey, err := cryptoutils.MarshalPublicKeyToPEM(intermediateSigner.Public())
	if err != nil {
		return nil, err
	}

	// OID for Extended Key Usage Timestamping
	timestampExt, err := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}})
	if err != nil {
		return nil, err
	}
	additionalExtensions := []*privatecapb.X509Extension{{
		ObjectId: &privatecapb.ObjectId{ObjectIdPath: []int32{2, 5, 29, 37}},
		Critical: true,
		Value:    timestampExt,
	}}

	isCa := true
	// default value of 0 for int32
	var maxIssuerPathLength int32

	csr := &privatecapb.CreateCertificateRequest{
		Parent: parent,
		Certificate: &privatecapb.Certificate{
			// Default to a very large lifetime - CA Service will truncate the
			// lifetime to be no longer than the root's lifetime.
			// 20 years (24 hours * 365 days * 20)
			Lifetime: durationpb.New(time.Hour * 24 * 365 * 20),
			CertificateConfig: &privatecapb.Certificate_Config{
				Config: &privatecapb.CertificateConfig{
					PublicKey: &privatecapb.PublicKey{
						Format: privatecapb.PublicKey_PEM,
						Key:    pemPubKey,
					},
					X509Config: &privatecapb.X509Parameters{
						KeyUsage: &privatecapb.KeyUsage{
							BaseKeyUsage: &privatecapb.KeyUsage_KeyUsageOptions{
								CertSign: true,
								CrlSign:  true,
							},
						},
						CaOptions: &privatecapb.X509Parameters_CaOptions{
							IsCa:                &isCa,
							MaxIssuerPathLength: &maxIssuerPathLength,
						},
						AdditionalExtensions: additionalExtensions,
					},
					SubjectConfig: &privatecapb.CertificateConfig_SubjectConfig{
						Subject: &privatecapb.Subject{
							CommonName:   "sigstore-tsa-intermediate",
							Organization: "sigstore.dev",
						},
					},
				},
			},
		},
	}

	resp, err := client.CreateCertificate(ctx, csr)
	if err != nil {
		return nil, err
	}

	var pemCerts []string
	pemCerts = append(pemCerts, resp.PemCertificate)
	pemCerts = append(pemCerts, resp.PemCertificateChain...)

	var parsedCerts []*x509.Certificate
	for _, c := range pemCerts {
		certs, err := cryptoutils.UnmarshalCertificatesFromPEM([]byte(c))
		if err != nil {
			return nil, err
		}
		if len(certs) != 1 {
			return nil, errors.New("unexpected number of certificates returned")
		}
		parsedCerts = append(parsedCerts, certs[0])
	}
	intermediate := parsedCerts[0]

	// generate leaf certificate
	leafKMSSigner, err := kms.Get(ctx, leafKMSKey, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	leafSigner, _, err := leafKMSSigner.CryptoSigner(ctx, func(err error) {})
	if err != nil {
		return nil, err
	}
	sn, err := cryptoutils.GenerateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("generating serial number: %w", err)
	}
	cert := &x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			CommonName:   "sigstore-tsa",
			Organization: []string{"sigstore.dev"},
		},
		NotBefore: intermediate.NotBefore,
		NotAfter:  intermediate.NotAfter,
		IsCA:      false,
		KeyUsage:  x509.KeyUsageDigitalSignature,
		// set EKU to x509.ExtKeyUsageTimeStamping but with a critical bit
		ExtraExtensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 37},
				Critical: true,
				Value:    timestampExt,
			},
		},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, cert, intermediate, leafSigner.Public(), intermediateSigner)
	if err != nil {
		return nil, fmt.Errorf("creating tsa certificate: %w", err)
	}
	leafCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parsing leaf certificate: %w", err)
	}
	parsedCerts = append(parsedCerts, leafCert)

	return parsedCerts, nil
}

func main() {
	flag.Parse()

	if *gcpCaParent == "" {
		log.Fatal("gcp-ca-parent must be set")
	}
	if *intermediateKMSKey == "" {
		log.Fatal("intermediate-kms-resource must be set")
	}
	if *leafKMSKey == "" {
		log.Fatal("leaf-kms-resource must be set")
	}
	if *outputPath == "" {
		log.Fatal("output must be set")
	}

	client, err := privateca.NewCertificateAuthorityClient(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	parsedCerts, err := fetchCACertificate(context.Background(), *gcpCaParent, *intermediateKMSKey, *leafKMSKey, client)
	if err != nil {
		log.Fatal(err)
	}
	pemCerts, err := cryptoutils.MarshalCertificatesToPEM(parsedCerts)
	if err != nil {
		log.Fatal(err)
	}

	err = os.WriteFile(*outputPath, pemCerts, 0600)
	if err != nil {
		log.Fatal(err)
	}
}
