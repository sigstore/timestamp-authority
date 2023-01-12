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
	"errors"
	"testing"

	"github.com/beevik/ntp"
)

type MockNTPClient struct{}

func (c MockNTPClient) QueryWithOptions(srv string, opts ntp.QueryOptions) (*ntp.Response, error) {
	return &ntp.Response{
		ClockOffset: 1,
	}, nil
}

type FailNTPClient struct{}

func (c FailNTPClient) QueryWithOptions(srv string, opts ntp.QueryOptions) (*ntp.Response, error) {
	return &ntp.Response{}, errors.New("failed to query NTP server(s)")
}

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

	// Number of servers are smaller than requested
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

func TestNTPMonitorQueryNTPServer(t *testing.T) {
	mockNTP := MockNTPClient{}
	failNTP := FailNTPClient{}

	testCases := []struct {
		name             string
		client           NTPClient
		expectTestToPass bool
	}{
		{
			name:             "Successfully Query NTP Server",
			client:           mockNTP,
			expectTestToPass: true,
		},
		{
			name:             "Successfully Query NTP Server",
			client:           failNTP,
			expectTestToPass: false,
		},
	}
	for _, tc := range testCases {
		monitor := NTPMonitor{
			cfg: &Config{
				RequestAttempts: 3,
			},
			ntpClient: tc.client,
		}

		resp, err := monitor.QueryNTPServer("some-server")
		if tc.expectTestToPass && err != nil {
			t.Errorf("test '%s' unexpectedly failed with non-nil error: %v", tc.name, err)
		}
		if tc.expectTestToPass && resp == nil {
			t.Errorf("test '%s' unexpectedly failed with nil ntp.Response: %v", tc.name, resp)
		}
		if !tc.expectTestToPass && err == nil {
			t.Errorf("test '%s' unexpectedly passed with a nil error", tc.name)
		}
	}
}
