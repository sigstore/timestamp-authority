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

package tests

import (
	"bytes"
	"crypto"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	ts "github.com/digitorus/timestamp"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/timestamp-authority/v2/pkg/client"
	"github.com/sigstore/timestamp-authority/v2/pkg/generated/client/timestamp"
)

const (
	cli = "../../bin/timestamp-cli"
)

func TestInspect(t *testing.T) {
	serverURL := createServer(t)

	tsrPath := getTimestamp(t, serverURL, "blob", big.NewInt(0), nil, true)

	// It should create timestamp successfully.
	out := runCli(t, "inspect", "--timestamp", tsrPath, "--format", "json")

	// test that output can be parsed as a timestamp
	resp := struct {
		TimestampResponse ts.Timestamp
	}{}

	err := json.Unmarshal([]byte(out), &resp)
	if err != nil {
		t.Errorf("failed to parse CLI response to a timestamp: %v", err)
	}
}

func TestTimestamp(t *testing.T) {
	restapiURL := createServer(t)

	tsrPath := filepath.Join(t.TempDir(), "response.tsr")

	artifactPath := makeArtifact(t, "blob")

	// It should create timestamp successfully.
	out := runCli(t, "--timestamp_server", restapiURL, "timestamp", "--artifact", artifactPath, "--hash", "sha256", "--out", tsrPath)
	outputContains(t, out, "Artifact timestamped at")

	if _, err := os.Stat(tsrPath); errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected TSR file does not exist at path %s", tsrPath)
	}
}

func TestVerify_CertificateChainFlag(t *testing.T) {
	restapiURL := createServer(t)

	artifactContent := "blob"
	artifactPath := makeArtifact(t, artifactContent)

	// this is the common name for the in-memory leaf certificate, copied
	// from pkg/signer/memory.go
	commonName := "Test TSA Timestamping"
	nonce := big.NewInt(456)
	policyOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 2}
	tsrContainsCerts := true

	tsrPath := getTimestamp(t, restapiURL, artifactContent, nonce, policyOID, tsrContainsCerts)

	// write the cert chain to a PEM file
	pemFiles := writeCertChainToPEMFiles(t, restapiURL)

	// It should verify timestamp successfully.
	out := runCli(t, "--timestamp_server", restapiURL, "verify", "--timestamp", tsrPath, "--artifact", artifactPath, "--certificate-chain", pemFiles.certChainPath, "--nonce", nonce.String(), "--oid", policyOID.String(), "--common-name", commonName)
	outputContains(t, out, "Successfully verified timestamp")
}

func TestVerify_RootAndIntermediateCertificateFlags(t *testing.T) {
	restapiURL := createServer(t)

	artifactContent := "blob"
	artifactPath := makeArtifact(t, artifactContent)

	// this is the common name for the in-memory leaf certificate, copied
	// from pkg/signer/memory.go
	commonName := "Test TSA Timestamping"
	nonce := big.NewInt(456)
	policyOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 2}
	tsrContainsCerts := true

	tsrPath := getTimestamp(t, restapiURL, artifactContent, nonce, policyOID, tsrContainsCerts)

	// write the cert chain to a PEM file
	pemFiles := writeCertChainToPEMFiles(t, restapiURL)

	// It should verify timestamp successfully.
	out := runCli(t, "--timestamp_server", restapiURL, "verify", "--timestamp", tsrPath, "--artifact", artifactPath, "--root-certificates", pemFiles.rootCertsPath, "--intermediate-certificates", pemFiles.intermediateCertsPath, "--nonce", nonce.String(), "--oid", policyOID.String(), "--common-name", commonName)
	outputContains(t, out, "Successfully verified timestamp")
}

func TestVerify_AllCertFlagsIncluded(t *testing.T) {
	restapiURL := createServer(t)

	artifactContent := "blob"
	artifactPath := makeArtifact(t, artifactContent)

	// this is the common name for the in-memory leaf certificate, copied
	// from pkg/signer/memory.go
	commonName := "Test TSA Timestamping"
	nonce := big.NewInt(456)
	policyOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 2}
	tsrContainsCerts := true

	tsrPath := getTimestamp(t, restapiURL, artifactContent, nonce, policyOID, tsrContainsCerts)

	// write the cert chain to a PEM file
	pemFiles := writeCertChainToPEMFiles(t, restapiURL)

	// It should fail to verify.
	out := runCliErr(t, "--timestamp_server", restapiURL, "verify", "--timestamp", tsrPath, "--artifact", artifactPath, "--certificate-chain", pemFiles.certChainPath, "--root-certificates", pemFiles.rootCertsPath, "--intermediate-certificates", pemFiles.intermediateCertsPath, "--nonce", nonce.String(), "--oid", policyOID.String(), "--common-name", commonName)
	outputContains(t, out, "the verify command must be called with either only the --certificate-chain flag or with the --root-certificates and --intermediate-certificates flags")
}

func TestVerify_NoCertFlagsIncluded(t *testing.T) {
	restapiURL := createServer(t)

	artifactContent := "blob"
	artifactPath := makeArtifact(t, artifactContent)

	// this is the common name for the in-memory leaf certificate, copied
	// from pkg/signer/memory.go
	commonName := "Test TSA Timestamping"
	nonce := big.NewInt(456)
	policyOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 2}
	tsrContainsCerts := true

	tsrPath := getTimestamp(t, restapiURL, artifactContent, nonce, policyOID, tsrContainsCerts)

	// It should fail to verify.
	out := runCliErr(t, "--timestamp_server", restapiURL, "verify", "--timestamp", tsrPath, "--artifact", artifactPath, "--nonce", nonce.String(), "--oid", policyOID.String(), "--common-name", commonName)
	outputContains(t, out, "the verify command must be called with either only the --certificate-chain flag or with the --root-certificates and --intermediate-certificates flags")
}

func TestVerify_PassLeafCertificate(t *testing.T) {
	restapiURL := createServer(t)

	artifactContent := "blob"
	artifactPath := makeArtifact(t, artifactContent)

	// this is the common name for the in-memory leaf certificate, copied
	// from pkg/signer/memory.go
	commonName := "Test TSA Timestamping"
	nonce := big.NewInt(456)
	policyOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 2}
	tsrContainsCerts := false

	tsrPath := getTimestamp(t, restapiURL, artifactContent, nonce, policyOID, tsrContainsCerts)

	// write the cert chain to a PEM file
	pemFiles := writeCertChainToPEMFiles(t, restapiURL)

	// It should verify timestamp successfully.
	out := runCli(t, "--timestamp_server", restapiURL, "verify", "--timestamp", tsrPath, "--artifact", artifactPath, "--certificate-chain", pemFiles.certChainPath, "--nonce", nonce.String(), "--oid", policyOID.String(), "--common-name", commonName, "--certificate", pemFiles.leafCertPath)
	outputContains(t, out, "Successfully verified timestamp")
}

func TestVerify_InvalidTSR(t *testing.T) {
	restapiURL := createServer(t)

	pemFiles := writeCertChainToPEMFiles(t, restapiURL)

	artifactContent := "blob"
	artifactPath := makeArtifact(t, artifactContent)

	// Create invalid pem
	invalidTSR := filepath.Join(t.TempDir(), "response.tsr")
	if err := os.WriteFile(invalidTSR, []byte("invalid TSR"), 0600); err != nil {
		t.Fatal(err)
	}

	// It should return a message that the PEM is not valid
	out := runCliErr(t, "--timestamp_server", restapiURL, "verify", "--timestamp", invalidTSR, "--artifact", artifactPath, "--certificate-chain", pemFiles.certChainPath)
	outputContains(t, out, "error parsing response into Timestamp")
}

func TestVerify_InvalidPEM(t *testing.T) {
	restapiURL := createServer(t)

	artifactContent := "blob"
	artifactPath := makeArtifact(t, artifactContent)

	tsrPath := getTimestamp(t, restapiURL, artifactContent, big.NewInt(0), nil, true)

	// Create invalid pem
	invalidPEMPath := filepath.Join(t.TempDir(), "invalid_pem_path")
	if err := os.WriteFile(invalidPEMPath, []byte("invalid PEM"), 0600); err != nil {
		t.Fatal(err)
	}

	// It should return a message that the PEM is not valid
	out := runCliErr(t, "--timestamp_server", restapiURL, "verify", "--timestamp", tsrPath, "--artifact", artifactPath, "--certificate-chain", invalidPEMPath)
	outputContains(t, out, "failed to parse intermediate and root certs from PEM file")
}

func runCliErr(t *testing.T, arg ...string) string {
	t.Helper()

	// use a blank config file to ensure no collision
	if os.Getenv("TSATMPDIR") != "" {
		arg = append(arg, "--config="+os.Getenv("TSATMPDIR")+".timestamp-server.yaml")
	}
	cmd := exec.Command(cli, arg...)
	b, err := cmd.CombinedOutput()
	if err == nil {
		t.Log(string(b))
		t.Fatalf("expected error, got %s", string(b))
	}
	return string(b)
}

func runCli(t *testing.T, arg ...string) string {
	t.Helper()

	// use a blank config file to ensure no collision
	if os.Getenv("TSATMPDIR") != "" {
		arg = append(arg, "--config="+os.Getenv("TSATMPDIR")+".timestamp-server.yaml")
	}
	return run(t, "", cli, arg...)
}

func run(t *testing.T, stdin, cmd string, arg ...string) string {
	t.Helper()
	c := exec.Command(cmd, arg...)
	if stdin != "" {
		c.Stdin = strings.NewReader(stdin)
	}
	if os.Getenv("TSATMPDIR") != "" {
		// ensure that we use a clean state.json file for each run
		c.Env = append(c.Env, "HOME="+os.Getenv("TSATMPDIR"))
	}
	b, err := c.CombinedOutput()
	if err != nil {
		t.Log(string(b))
		t.Fatal(err)
	}
	return string(b)
}

func outputContains(t *testing.T, output, sub string) {
	t.Helper()
	if !strings.Contains(output, sub) {
		t.Errorf("Expected [%s] in response, got %s", sub, output)
	}
}

func getTimestamp(t *testing.T, url string, artifactContent string, nonce *big.Int, policyOID asn1.ObjectIdentifier, tsrContainsCerts bool) string {
	c, err := client.GetTimestampClient(url, client.WithUserAgent("test user agent"), client.WithContentType(client.TimestampQueryMediaType))
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	tsNonce := big.NewInt(1234)
	if nonce != nil {
		tsNonce = nonce
	}

	tsPolicyOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 2}
	if policyOID != nil {
		tsPolicyOID = policyOID
	}

	tsq, err := ts.CreateRequest(strings.NewReader(artifactContent), &ts.RequestOptions{
		Hash:         crypto.SHA256,
		Certificates: tsrContainsCerts,
		Nonce:        tsNonce,
		TSAPolicyOID: tsPolicyOID,
	})
	if err != nil {
		t.Fatalf("unexpected error creating request: %v", err)
	}

	params := timestamp.NewGetTimestampResponseParams()
	params.Request = io.NopCloser(bytes.NewReader(tsq))

	var respBytes bytes.Buffer
	_, _, err = c.Timestamp.GetTimestampResponse(params, &respBytes)
	if err != nil {
		t.Fatalf("unexpected error getting timestamp chain: %v", err)
	}

	path := filepath.Join(t.TempDir(), "response.tsr")
	if err := os.WriteFile(path, respBytes.Bytes(), 0600); err != nil {
		t.Fatalf("unexpected error while writing timestamp to file: %v", err)
	}

	return path
}

type certChainPEMFiles struct {
	leafCertPath          string
	intermediateCertsPath string
	rootCertsPath         string
	certChainPath         string
}

// getCertChainPEM returns the path of a pem file containing
// the leaf certificate and the path of a pem file containing the
// root and intermediate certificates. Used to verify a signed timestamp
func writeCertChainToPEMFiles(t *testing.T, restapiURL string) certChainPEMFiles {
	c, err := client.GetTimestampClient(restapiURL)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	chain, err := c.Timestamp.GetTimestampCertChain(nil)
	if err != nil {
		t.Fatalf("unexpected error getting timestamp chain: %v", err)
	}

	// create PEM file containing intermediate and root certificates
	certChainPath := filepath.Join(t.TempDir(), "ts_certchain.pem")
	file, err := os.Create(certChainPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	// Remove the non-CA certificate from the chain
	certs, err := cryptoutils.UnmarshalCertificatesFromPEM([]byte(chain.Payload))
	if err != nil {
		t.Fatalf("unexpected error unmarshalling cert chain: %v", err)
	}
	caCertsPEM, err := cryptoutils.MarshalCertificatesToPEM(certs[1:])
	if err != nil {
		t.Fatalf("unexpected error marshalling cert chain: %v", err)
	}

	reader := bytes.NewReader(caCertsPEM)
	file.ReadFrom(reader)

	// create intermediates certificate PEM file
	intermediateCertsPath := filepath.Join(t.TempDir(), "ts_intermediates.pem")
	file, err = os.Create(intermediateCertsPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	lastCertIndex := len(certs) - 1
	intermediatesPEM, err := cryptoutils.MarshalCertificatesToPEM(certs[1:lastCertIndex])
	if err != nil {
		t.Fatalf("unexpected error marshalling intermediate certificates: %v", err)
	}

	reader = bytes.NewReader(intermediatesPEM)
	file.ReadFrom(reader)

	// create roots certificate PEM file
	rootCertsPath := filepath.Join(t.TempDir(), "ts_roots.pem")
	file, err = os.Create(rootCertsPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	rootsPEM, err := cryptoutils.MarshalCertificatesToPEM(certs[lastCertIndex:])
	if err != nil {
		t.Fatalf("unexpected error marshalling root certificates: %v", err)
	}

	reader = bytes.NewReader(rootsPEM)
	file.ReadFrom(reader)

	// create PEM file containing the leaf certificate
	leafCertPath := filepath.Join(t.TempDir(), "ts_leafcert.pem")
	file, err = os.Create(leafCertPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	leafCertPEM, err := cryptoutils.MarshalCertificatesToPEM(certs[0:1])
	if err != nil {
		t.Fatalf("unexpected error marshalling leaf cert: %v", err)
	}

	reader = bytes.NewReader(leafCertPEM)
	file.ReadFrom(reader)

	return certChainPEMFiles{
		leafCertPath:          leafCertPath,
		intermediateCertsPath: intermediateCertsPath,
		rootCertsPath:         rootCertsPath,
		certChainPath:         certChainPath,
	}
}

// Create a random artifact to sign
func makeArtifact(t *testing.T, content string) string {
	artifactPath := filepath.Join(t.TempDir(), "artifact")
	if err := os.WriteFile(artifactPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return artifactPath
}
