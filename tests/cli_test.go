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
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigstore/timestamp-authority/pkg/client"
)

var (
	restapiURL string
)

func getCertChainPEMRestCall(t *testing.T) string {
	pemFileName := "e2e_test_ts_chain.pem"

	resp, err := http.Get("http://localhost:3000/api/v1/timestamp/certchain")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	file, err := os.Create(pemFileName)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	file.ReadFrom(resp.Body)

	return pemFileName
}

func getCertChainPEM(t *testing.T) string {
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
func makeArtifact(t *testing.T) string {
	artifactPath := filepath.Join(t.TempDir(), "artifact")
	if err := os.WriteFile(artifactPath, []byte("some data"), 0600); err != nil {
		t.Fatal(err)
	}
	return artifactPath
}

func TestMain(m *testing.M) {
	restapiURL = createServer()
	m.Run()
}

func TestTimestampCreation(t *testing.T) {
	tsrPath := "response.tsr"
	artifactPath := makeArtifact(t)

	// It should create timestamp successfully.
	out := runCli(t, "--timestamp_server", restapiURL, "--timestamp_server", restapiURL, "timestamp", "--artifact", artifactPath, "--hash", "sha256", "--out", tsrPath)
	outputContains(t, out, "Artifact timestamped at")

	if _, err := os.Stat(tsrPath); errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected TSR file does not exist at path %s", tsrPath)
	}
}

func TestTimestampVerify(t *testing.T) {
	tsrPath := "response.tsr"

	artifactPath := makeArtifact(t)

	// write the cert chain to a PEM file
	pemPath := getCertChainPEM(t)

	// It should verify timestamp successfully.
	out := runCli(t, "--timestamp_server", restapiURL, "verify", "--timestamp", tsrPath, "--artifact", artifactPath, "--cert-chain", pemPath)
	outputContains(t, out, "Successfully verified timestamp")
}

func TestTimestampVerify_InvalidTSR(t *testing.T) {
	pemPath := "ts_chain.pem"
	if err := os.WriteFile(pemPath, []byte("stuff"), 0600); err != nil {
		t.Fatal(err)
	}

	artifactPath := makeArtifact(t)

	// Create invalid pem
	invalidTSR := filepath.Join(t.TempDir(), "response.tsr")
	if err := os.WriteFile(invalidTSR, []byte("invalid TSR"), 0600); err != nil {
		t.Fatal(err)
	}

	// It should return a message that the PEM is not valid
	out := runCliErr(t, "--timestamp_server", restapiURL, "verify", "--timestamp", invalidTSR, "--artifact", artifactPath, "--cert-chain", pemPath)
	outputContains(t, out, "error parsing response into Timestamp")
}

func TestTimestampVerify_InvalidPEM(t *testing.T) {
	tsrPath := "response.tsr"

	artifactPath := makeArtifact(t)

	// Create invalid pem
	invalidPEMPath := filepath.Join(t.TempDir(), "ts_chain.pem")
	if err := os.WriteFile(invalidPEMPath, []byte("invalid PEM"), 0600); err != nil {
		t.Fatal(err)
	}

	// It should return a message that the PEM is not valid
	out := runCliErr(t, "--timestamp_server", restapiURL, "verify", "--timestamp", tsrPath, "--artifact", artifactPath, "--cert-chain", invalidPEMPath)
	outputContains(t, out, "error while appending certs from PEM")
}
