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
)

var yamlData = `
# Number of attempts to contact a ntp server before giving up.
request_attempts: 3
# The timeout in seconds for a request to respond. This value must be
# smaller than max_time_delta.
request_timeout: 5
# Number of randomly selected ntp servers to interrogate.
num_servers: 4
# Number of servers who must agree with local time.
server_threshold: 3
# Maximum number of seconds the local time is allowed to drift from the
# response of a ntp server
max_time_delta: 6
# Period (in seconds) for polling ntp servers
period: 60
# List of servers to contact. Many DNS names resolves to multiple A records.
servers:
  #
  # stratum 1 servers:
  #
  # Apple AS6185
  - "time.apple.com"

  # Google AS15169
  - "time.google.com"
  - "time1.google.com"
  - "time2.google.com"
  - "time3.google.com"
  - "time4.google.com"
`

func TestLoadConfig(t *testing.T) {
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

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil {
		t.Fatal("no config returned")
	}

	if cfg.RequestAttempts != 3 {
		t.Errorf("request attempts, got %d expected %d",
			cfg.RequestAttempts, 3)
	}
	if cfg.RequestTimeout != 5 {
		t.Errorf("request timeout, got %d expected %d",
			cfg.RequestTimeout, 5)
	}
	if cfg.NumServers != 4 {
		t.Errorf("num servers, got %d expected %d",
			cfg.NumServers, 4)
	}
	if cfg.ServerThreshold != 3 {
		t.Errorf("server threshold, got %d expected %d",
			cfg.ServerThreshold, 3)
	}
	if cfg.MaxTimeDelta != 6 {
		t.Errorf("max time delta, got %d expected %d",
			cfg.MaxTimeDelta, 6)
	}
	if cfg.Period != 60 {
		t.Errorf("period, got %d expected %d",
			cfg.Period, 60)
	}
	if len(cfg.Servers) != 6 {
		t.Errorf("number of servers in list, got %d expected %d",
			len(cfg.Servers), 6)
	}
}
