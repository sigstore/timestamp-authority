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
	"testing"
)

func TestNewFromConfig(t *testing.T) {
	var cfg Config
	var nm *NTPMonitor
	var err error

	// No servers listed
	nm, err = NewFromConfig(&cfg)
	if nm != nil {
		t.Error("non expected monitor returned")
	}
	if err != ErrTooFewServers {
		t.Errorf("expected error %s got %s", ErrTooFewServers, err)
	}

	// Number of servers are smaller than requsted
	cfg.Servers = append(cfg.Servers, "foo.bar")
	cfg.NumServers = 2
	nm, err = NewFromConfig(&cfg)
	if nm != nil {
		t.Error("non expected monitor returned")
	}
	if err != ErrTooFewServers {
		t.Errorf("expected error %s got %s", ErrTooFewServers, err)
	}

	// Add a new server so len(servers) == num servers
	cfg.Servers = append(cfg.Servers, "foo.bar")

	// Threshold smaller than num servers
	cfg.ServerThreshold = 3
	nm, err = NewFromConfig(&cfg)
	if nm != nil {
		t.Error("non expected monitor returned")
	}
	if err != ErrTooFewServers {
		t.Errorf("expected error %s got %s", ErrTooFewServers, err)
	}

	// Set threshold to zero
	cfg.ServerThreshold = 0
	nm, err = NewFromConfig(&cfg)
	if nm != nil {
		t.Error("non expected monitor returned")
	}
	if err != ErrThreshold {
		t.Errorf("expected error %s got %s", ErrThreshold, err)
	}

	// Set threshold to two (len of servers)
	cfg.ServerThreshold = 2

	// Max delta is 0
	nm, err = NewFromConfig(&cfg)
	if nm != nil {
		t.Error("non expected monitor returned")
	}
	if err != ErrDeltaTooSmall {
		t.Errorf("expected error %s got %s", ErrDeltaTooSmall, err)
	}

	// Max delta is greater than request timeout
	cfg.RequestTimeout = 1
	nm, err = NewFromConfig(&cfg)
	if nm != nil {
		t.Error("non expected monitor returned")
	}
	if err != ErrDeltaTooSmall {
		t.Errorf("expected error %s got %s", ErrDeltaTooSmall, err)
	}

	// Valid config
	cfg.MaxTimeDelta = 1
	nm, err = NewFromConfig(&cfg)
	if nm == nil {
		t.Error("expected monitor returned")
	}
	if err != nil {
		t.Errorf("unexpected error %s", err)
	}
}
