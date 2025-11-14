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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/spf13/viper"

	"github.com/sigstore/timestamp-authority/v2/pkg/server"
)

func createServer(t *testing.T, flagsToSet ...func()) string {
	viper.Set("timestamp-signer", "memory")
	viper.Set("timestamp-signer-hash", "sha256")
	for _, flag := range flagsToSet {
		flag()
	}
	// unused port
	apiServer := server.NewRestAPIServer("localhost", 0, []string{"http"}, false, 10*time.Second, 10*time.Second)
	server := httptest.NewServer(apiServer.GetHandler())
	t.Cleanup(server.Close)

	// verify the server's health
	response, err := http.Get(server.URL + "/ping")
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("unexpected error starting up server - status code: %d, err: %v", response.StatusCode, err)
	}
	defer response.Body.Close()

	return server.URL
}
