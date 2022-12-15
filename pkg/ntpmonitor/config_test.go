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

package ntpmonitor

import (
	"os"
	"path"
	"testing"

	"gopkg.in/yaml.v3"
)

var yamlData = `
# Number of attempts to contact a ntp server before giving up.
request_attempts: 2
# The timeout in seconds for a request to respond. This value must be
# smaller than max_time_delta.
request_timeout: 1
# Number of randomly selected ntp servers to interrogate.
num_servers: 2
# Number of servers who must agree with local time.
server_threshold: 1
# Maximum number of seconds the local time is allowed to drift from the
# response of a ntp server
max_time_delta: 2
# Period (in seconds) for polling ntp servers
period: 80
# List of servers to contact. Many DNS names resolves to multiple A records.
servers:
  #
  # stratum 1 servers:
  #
  # Apple AS6185
  - "time.apple.com"

  # Google AS15169
  - "time.google.com"
`

func TestLoadConfig(t *testing.T) {
	// create test custom config for testing
	var dir = t.TempDir()
	var path = path.Join(dir, "cfg.yaml")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}

	if _, err = f.Write([]byte(yamlData)); err != nil {
		t.Fatal(err)
	}
	f.Close()

	// create default config for testing
	var defaultConfig Config
	if err = yaml.Unmarshal(defaultConfigData, &defaultConfig); err != nil {
		t.Fatalf("failed to parse default config YAML: %v", err)
	}

	type test struct {
		configPath     string
		expectedConfig Config
	}

	tests := []test{
		{
			configPath: path,
			expectedConfig: Config{
				RequestAttempts: 2,
				RequestTimeout:  1,
				NumServers:      2,
				ServerThreshold: 1,
				MaxTimeDelta:    2,
				Period:          80,
				Servers:         []string{"a", "b"},
			},
		},
		{
			configPath:     "ntpsync.yaml",
			expectedConfig: defaultConfig,
		},
	}

	for _, tc := range tests {
		cfg, err := LoadConfig(tc.configPath)
		if err != nil {
			t.Fatal(err)
		}
		if cfg == nil {
			t.Fatal("no config returned")
		}

		if cfg.RequestAttempts != tc.expectedConfig.RequestAttempts {
			t.Errorf("request attempts, got %d expected %d",
				cfg.RequestAttempts, tc.expectedConfig.RequestAttempts)
		}
		if cfg.RequestTimeout != tc.expectedConfig.RequestTimeout {
			t.Errorf("request timeout, got %d expected %d",
				cfg.RequestTimeout, tc.expectedConfig.RequestTimeout)
		}
		if cfg.NumServers != tc.expectedConfig.NumServers {
			t.Errorf("num servers, got %d expected %d",
				cfg.NumServers, tc.expectedConfig.NumServers)
		}
		if cfg.ServerThreshold != tc.expectedConfig.ServerThreshold {
			t.Errorf("server threshold, got %d expected %d",
				cfg.ServerThreshold, tc.expectedConfig.ServerThreshold)
		}
		if cfg.MaxTimeDelta != tc.expectedConfig.MaxTimeDelta {
			t.Errorf("max time delta, got %d expected %d",
				cfg.MaxTimeDelta, tc.expectedConfig.MaxTimeDelta)
		}
		if cfg.Period != tc.expectedConfig.Period {
			t.Errorf("period, got %d expected %d",
				cfg.Period, tc.expectedConfig.Period)
		}
		if len(cfg.Servers) != len(tc.expectedConfig.Servers) {
			t.Errorf("number of servers in list, got %d expected %d",
				len(cfg.Servers), len(tc.expectedConfig.Servers))
		}
	}
}
