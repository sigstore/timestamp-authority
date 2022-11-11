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
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds the configuration for a NTPMonitor
type Config struct {
	RequestRetries  int      `yaml:"request_retries"`
	NumServers      int      `yaml:"num_servers"`
	MaxTimeDelta    int      `yaml:"max_time_delta"`
	ServerThreshold int      `yaml:"server_threshold"`
	Period          int      `yaml:"period"`
	Servers         []string `yaml:"servers"`
}

// LoadConfig reads a yaml file from a provided path, instantiating a new
// Config object with the vales found. No sanity checking is made of the
// loaded values.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %s %w",
			path, err)
	}

	var cfg Config
	if err = yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	return &cfg, nil
}
