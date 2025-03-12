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
	"path/filepath"
	"time"

	privateca "cloud.google.com/go/security/privateca/apiv1"
	"cloud.google.com/go/security/privateca/apiv1/privatecapb"
	"github.com/google/tink/go/keyset"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/timestamp-authority/pkg/signer"
	tsx509 "github.com/sigstore/timestamp-authority/pkg/x509"
	"google.golang.org/protobuf/types/known/durationpb"

	// Register the provider-specific plugins
	"github.com/sigstore/sigstore/pkg/signature/kms"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/aws"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/azure"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/gcp"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/hashivault"
)

/*
Create certificate chain with a KMS signing key, a KMS intermediate and a CA root:

  go run cmd/fetch-tsa-certs/fetch_tsa_certs.go \
    --intermediate-kms-resource="gcpkms://projects/<project>/locations/<region>/keyRings/<key-ring>/cryptoKeys/<key>/versions/1" \
    --leaf-kms-resource="gcpkms://projects/<project>/locations/<region>/keyRings/<leaf-key-ring>/cryptoKeys/<key>/versions/1" \
    --gcp-ca-parent="projects/<project>/locations/<region>/caPools/<ca-pool>" \
    --output="chain.crt.pem"

Create certificate chain with a Tink signing key encrypted with KMS KEK, a KMS intermediate and a CA root:

  go run cmd/fetch-tsa-certs/fetch_tsa_certs.go \
    --intermediate-kms-resource="gcpkms://projects/<project>/locations/<region>/keyRings/<key-ring>/cryptoKeys/<key>/versions/1" \
    --tink-kms-resource="gcp-kms://projects/<project>/locations/<region>/keyRings/<key-ring>/cryptoKeys/<key>" \
    --tink-keyset-path="enc-keyset.cfg" \
    --gcp-ca-parent="projects/<project>/locations/<region>/caPools/<ca-pool>" \
    --output="chain.crt.pem"

Create certificate chain with a Tink signing key encrypted with KMS KEK and a self-signed parent certificate:

  go run cmd/fetch-tsa-certs/fetch_tsa_certs.go \
    --intermediate-kms-resource="gcpkms://projects/<project>/locations/<region>/keyRings/<key-ring>/cryptoKeys/<key>/versions/1" \
    --tink-kms-resource="gcp-kms://projects/<project>/locations/<region>/keyRings/<key-ring>/cryptoKeys/<key>" \
    --tink-keyset-path="enc-keyset.cfg" \
    --output="chain.crt.pem"

You must have the permissions to read, sign with, and decrypt with the KMS keys, and create a certificate in the CA pool.

You can create a GCP KMS encrypted Tink keyset with tinkey (changing the key template as needed):
tinkey create-keyset --key-template ECDSA_P384 --out enc-keyset.cfg --master-key-uri gcp-kms://projects/<project>/locations/<region>/keyRings/<key-ring>/cryptoKeys/<key>
*/

var (
	// likely the root CA
	gcpCaRoot = flag.String("gcp-ca-parent", "", "Resource path to GCP CA Service CA. If unset, the intermediate cert will be self-signed instead")
	// key only used for fetching intermediate certificate from root and signing leaf certificate
	intermediateKMSKey = flag.String("intermediate-kms-resource", "", "Resource path to the asymmetric signing KMS key for the intermediate CA, starting with gcpkms://, awskms://, azurekms:// or hashivault://")
	// leafKMSKey or Tink flags required
	leafKMSKey     = flag.String("leaf-kms-resource", "", "Resource path to the asymmetric signing KMS key for the leaf, starting with gcpkms://, awskms://, azurekms:// or hashivault://")
	tinkKeysetPath = flag.String("tink-keyset-path", "", "Path to Tink keyset")
	tinkKmsKey     = flag.String("tink-kms-resource", "", "Resource path to symmetric encryption KMS key to decrypt Tink keyset, starting with gcp-kms:// or aws-kms://")
	outputPath     = flag.String("output", "", "Path to the output file")
)

func fetchCertificateChain(ctx context.Context, root, parentKMSKey, leafKMSKey, tinkKeysetPath, tinkKmsKey string,
	client *privateca.CertificateAuthorityClient) ([]*x509.Certificate, error) {
	parentKMSSigner, err := kms.Get(ctx, parentKMSKey, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	parentSigner, _, err := parentKMSSigner.CryptoSigner(ctx, func(_ error) {})
	if err != nil {
		return nil, err
	}
	parentPubKey := parentSigner.Public()
	parentPEMPubKey, err := cryptoutils.MarshalPublicKeyToPEM(parentPubKey)
	if err != nil {
		return nil, err
	}

	// OID for Extended Key Usage Timestamping
	timestampExt, err := asn1.Marshal([]asn1.ObjectIdentifier{tsx509.EKUTimestampingOID})
	if err != nil {
		return nil, err
	}
	additionalExtensions := []*privatecapb.X509Extension{{
		ObjectId: &privatecapb.ObjectId{ObjectIdPath: []int32{2, 5, 29, 37}},
		Critical: true,
		Value:    timestampExt,
	}}

	var certChain []*x509.Certificate

	if root == "" {
		// Create a self signed signing certificate for parentPubKey
		parentSn, err := cryptoutils.GenerateSerialNumber()
		if err != nil {
			return nil, fmt.Errorf("generating serial number: %w", err)
		}

		parentSkid, err := cryptoutils.SKID(parentPubKey)
		if err != nil {
			return nil, fmt.Errorf("generating SKID hash: %w", err)
		}
		now := time.Now()
		cert := &x509.Certificate{
			SerialNumber: parentSn,
			Subject: pkix.Name{
				CommonName:   "sigstore-tsa-selfsigned",
				Organization: []string{"sigstore.dev"},
			},
			SubjectKeyId: parentSkid,
			NotBefore:    now,
			NotAfter:     now.AddDate(20, 0, 0),
			KeyUsage:     x509.KeyUsageCertSign,
		}
		ParentCertDER, err := x509.CreateCertificate(rand.Reader, cert, cert, parentPubKey, parentSigner)
		if err != nil {
			return nil, fmt.Errorf("creating self-signed parent certificate: %w", err)
		}
		parentCert, err := x509.ParseCertificate(ParentCertDER)
		if err != nil {
			return nil, fmt.Errorf("parsing leaf certificate: %w", err)
		}
		certChain = append(certChain, parentCert)

	} else {
		// Use CA to get an intermediate signing certificate for parentPubKey
		isCa := true
		// default value of 0 for int32
		var maxIssuerPathLength int32

		csr := &privatecapb.CreateCertificateRequest{
			Parent: root,
			Certificate: &privatecapb.Certificate{
				// Default to a very large lifetime - CA Service will truncate the
				// lifetime to be no longer than the root's lifetime.
				// 20 years (24 hours * 365 days * 20)
				Lifetime: durationpb.New(time.Hour * 24 * 365 * 20),
				CertificateConfig: &privatecapb.Certificate_Config{
					Config: &privatecapb.CertificateConfig{
						PublicKey: &privatecapb.PublicKey{
							Format: privatecapb.PublicKey_PEM,
							Key:    parentPEMPubKey,
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

		for _, c := range pemCerts {
			certs, err := cryptoutils.UnmarshalCertificatesFromPEM([]byte(c))
			if err != nil {
				return nil, err
			}
			if len(certs) != 1 {
				return nil, errors.New("unexpected number of certificates returned")
			}
			certChain = append(certChain, certs[0])
		}
	}

	// parent may be intermediate or self signed root
	parent := certChain[0]

	// generate leaf certificate
	var leafKMSSigner crypto.Signer
	if len(leafKMSKey) > 0 {
		kmsSigner, err := kms.Get(ctx, leafKMSKey, crypto.SHA256)
		if err != nil {
			return nil, err
		}
		leafKMSSigner, _, err = kmsSigner.CryptoSigner(ctx, func(_ error) {})
		if err != nil {
			return nil, err
		}
	} else {
		primaryKey, err := signer.GetPrimaryKey(ctx, tinkKmsKey, "")
		if err != nil {
			return nil, err
		}
		f, err := os.Open(filepath.Clean(tinkKeysetPath))
		if err != nil {
			return nil, err
		}
		defer f.Close()

		kh, err := keyset.Read(keyset.NewJSONReader(f), primaryKey)
		if err != nil {
			return nil, err
		}
		leafKMSSigner, err = signer.KeyHandleToSigner(kh)
		if err != nil {
			return nil, err
		}
	}

	leafPubKey := leafKMSSigner.Public()

	sn, err := cryptoutils.GenerateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("generating serial number: %w", err)
	}

	skid, err := cryptoutils.SKID(leafPubKey)
	if err != nil {
		return nil, err
	}

	cert := &x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			CommonName:   "sigstore-tsa",
			Organization: []string{"sigstore.dev"},
		},
		SubjectKeyId: skid,
		NotBefore:    parent.NotBefore,
		NotAfter:     parent.NotAfter,
		IsCA:         false,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		// set EKU to x509.ExtKeyUsageTimeStamping but with a critical bit
		ExtraExtensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 37},
				Critical: true,
				Value:    timestampExt,
			},
		},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, cert, parent, leafPubKey, parentSigner)
	if err != nil {
		return nil, fmt.Errorf("creating tsa certificate: %w", err)
	}
	leafCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parsing leaf certificate: %w", err)
	}
	certChain = append([]*x509.Certificate{leafCert}, certChain...)

	return certChain, nil
}

func main() {
	flag.Parse()

	if *intermediateKMSKey == "" {
		log.Fatal("intermediate-kms-resource must be set")
	}
	if *leafKMSKey == "" && *tinkKeysetPath == "" {
		log.Fatal("either leaf-kms-resource or tink-keyset-path must be set")
	}
	if *tinkKeysetPath != "" && *tinkKmsKey == "" {
		log.Fatal("tink-keyset-path must be set with tink-kms-resource must be set")
	}
	if *outputPath == "" {
		log.Fatal("output must be set")
	}

	client, err := privateca.NewCertificateAuthorityClient(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	parsedCerts, err := fetchCertificateChain(context.Background(), *gcpCaRoot, *intermediateKMSKey, *leafKMSKey, *tinkKeysetPath, *tinkKmsKey, client)
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
