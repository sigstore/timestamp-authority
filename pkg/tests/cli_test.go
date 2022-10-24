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
	"errors"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	ts "github.com/digitorus/timestamp"
	"github.com/sigstore/timestamp-authority/pkg/client"
	"github.com/sigstore/timestamp-authority/pkg/generated/client/timestamp"
)

const (
	cli = "../../timestamp-cli"
)

func TestTimestampCreation(t *testing.T) {
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

func TestTimestampVerify(t *testing.T) {
	restapiURL := createServer(t)

	artifactContent := "blob"
	artifactPath := makeArtifact(t, artifactContent)

	tsrPath := getTimestamp(t, restapiURL, artifactContent)

	// write the cert chain to a PEM file
	pemPath := getCertChainPEM(t, restapiURL)

	// It should verify timestamp successfully.
	out := runCli(t, "--timestamp_server", restapiURL, "verify", "--timestamp", tsrPath, "--artifact", artifactPath, "--cert-chain", pemPath)
	outputContains(t, out, "Successfully verified timestamp")
}

func TestTimestampVerify_InvalidTSR(t *testing.T) {
	restapiURL := createServer(t)

	pemPath := filepath.Join(t.TempDir(), "ts_chain.pem")
	if err := os.WriteFile(pemPath, []byte("stuff"), 0600); err != nil {
		t.Fatal(err)
	}

	artifactContent := "blob"
	artifactPath := makeArtifact(t, artifactContent)

	// Create invalid pem
	invalidTSR := filepath.Join(t.TempDir(), "response.tsr")
	if err := os.WriteFile(invalidTSR, []byte("invalid TSR"), 0600); err != nil {
		t.Fatal(err)
	}

	// It should return a message that the PEM is not valid
	out := runCliErr(t, "--timestamp_server", restapiURL, "verify", "--timestamp", invalidTSR, "--artifact", artifactPath, "--cert-chain", pemPath)
	outputContains(t, out, "Error parsing response into Timestamp")
}

func TestTimestampVerify_InvalidPEM(t *testing.T) {
	restapiURL := createServer(t)

	artifactContent := "blob"
	artifactPath := makeArtifact(t, artifactContent)

	tsrPath := getTimestamp(t, restapiURL, artifactContent)

	// Create invalid pem
	invalidPEMPath := filepath.Join(t.TempDir(), "ts_chain.pem")
	if err := os.WriteFile(invalidPEMPath, []byte("invalid PEM"), 0600); err != nil {
		t.Fatal(err)
	}

	// It should return a message that the PEM is not valid
	out := runCliErr(t, "--timestamp_server", restapiURL, "verify", "--timestamp", tsrPath, "--artifact", artifactPath, "--cert-chain", invalidPEMPath)
	outputContains(t, out, "Error while appending certs from PEM")
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

func getTimestamp(t *testing.T, url string, artifactContent string) string {
	c, err := client.GetTimestampClient(url)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	tsNonce := big.NewInt(1234)
	tsq, err := ts.CreateRequest(strings.NewReader(artifactContent), &ts.RequestOptions{
		Hash:         crypto.SHA256,
		Certificates: true,
		Nonce:        tsNonce,
	})
	if err != nil {
		t.Fatalf("unexpected error creating request: %v", err)
	}

	params := timestamp.NewGetTimestampResponseParams()
	params.Request = io.NopCloser(bytes.NewReader(tsq))

	var respBytes bytes.Buffer
	_, err = c.Timestamp.GetTimestampResponse(params, &respBytes)
	if err != nil {
		t.Fatalf("unexpected error getting timestamp chain: %v", err)
	}

	path := filepath.Join(t.TempDir(), "response.tsr")
	if err := os.WriteFile(path, respBytes.Bytes(), 0600); err != nil {
		t.Fatalf("unexpected error while writing timestamp to file: %v", err)
	}

	return path
}

func getCertChainPEM(t *testing.T, restapiURL string) string {
	c, err := client.GetTimestampClient(restapiURL)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	chain, err := c.Timestamp.GetTimestampCertChain(nil)
	if err != nil {
		t.Fatalf("unexpected error getting timestamp chain: %v", err)
	}

	path := filepath.Join(t.TempDir(), "artifact")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	reader := strings.NewReader(chain.Payload)
	file.ReadFrom(reader)

	return path
}

// Create a random artifact to sign
func makeArtifact(t *testing.T, content string) string {
	artifactPath := filepath.Join(t.TempDir(), "artifact")
	if err := os.WriteFile(artifactPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return artifactPath
}
