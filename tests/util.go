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
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"

	"github.com/sigstore/timestamp-authority/pkg/server"
)

const (
	cli = "../timestamp-cli"
)

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

func createServer() string {
	viper.Set("timestamp-signer", "memory")
	// unused port
	apiServer := server.NewRestAPIServer("localhost", 0, []string{"http"}, 10*time.Second, 10*time.Second)
	server := httptest.NewServer(apiServer.GetHandler())

	// verify the server's health
	response, err := http.Get(server.URL + "/ping")
	if err != nil || response.StatusCode != 200 {
		panic(fmt.Sprintf("unexpected error starting up server - status code: %d, err: %v", response.StatusCode, err))
	}

	return server.URL
}
