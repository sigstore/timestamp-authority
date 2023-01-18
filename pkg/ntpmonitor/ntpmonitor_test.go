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
	"time"

	"github.com/beevik/ntp"
	"github.com/prometheus/client_golang/prometheus/testutil"
	pkgapi "github.com/sigstore/timestamp-authority/pkg/api"
)

type MockNTPClient struct {
	// add the names of servers that MockNTPClient#QueryWithOptions should
	// always return an error response for
	ignoredServers map[string]string
}

func (c MockNTPClient) QueryWithOptions(srv string, _ ntp.QueryOptions) (*ntp.Response, error) {
	if _, ok := c.ignoredServers[srv]; ok {
		return nil, errors.New("failed to query NTP server")
	}

	return &ntp.Response{
		ClockOffset: 1,
		Time:        time.Now(),
	}, nil
}

type driftedTimeNTPClient struct {
	driftedOffset time.Duration
}

func (c driftedTimeNTPClient) QueryWithOptions(_ string, _ ntp.QueryOptions) (*ntp.Response, error) {
	return &ntp.Response{
		ClockOffset: c.driftedOffset,
		Time:        time.Now(),
	}, nil
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
	failNTP := MockNTPClient{
		ignoredServers: map[string]string{
			"s1": "",
		},
	}

	testCases := []struct {
		name             string
		client           MockNTPClient
		expectTestToPass bool
	}{
		{
			name:             "Successfully query NTP server",
			client:           mockNTP,
			expectTestToPass: true,
		},
		{
			name:             "Fail to query NTP server",
			client:           failNTP,
			expectTestToPass: false,
		},
	}

	// There does not seem to be a way to reset the metric counter for testing
	// purposes. To test that the metric counter value is incrementing by one
	// as expected, we can set this variable to zero before the test for loop
	// and increment it the call to monitor.queryNTPServer. We then check that
	// the metric value has only increased by one as expected
	expectedMetricValue := 0
	for _, tc := range testCases {
		monitor, err := NewFromConfigWithClient(&Config{
			Servers:         []string{"s1"},
			NumServers:      1,
			RequestAttempts: 1,
			ServerThreshold: 1,
			RequestTimeout:  1,
			MaxTimeDelta:    1,
		}, tc.client)
		if err != nil {
			t.Fatalf("unexpectedly failed to create NTP monitor: %v", err)
		}

		resp, err := monitor.queryNTPServer("s1")
		// increment the expected metric value
		expectedMetricValue++

		if tc.expectTestToPass && err != nil {
			t.Errorf("test '%s' unexpectedly failed with non-nil error: %v", tc.name, err)
		}
		if tc.expectTestToPass && resp == nil {
			t.Errorf("test '%s' unexpectedly failed with nil ntp.Response", tc.name)
		}
		if !tc.expectTestToPass && err == nil {
			t.Errorf("test '%s' unexpectedly passed with a nil error", tc.name)
		}
		// check that the actual metric value was incremented by one as expected
		actualMetricCount := testutil.CollectAndCount(pkgapi.MetricNTPSyncCount)
		if expectedMetricValue != actualMetricCount {
			t.Errorf("test '%s' unexpectedly failed with wrong metric value %d, expected %d", tc.name, actualMetricCount, expectedMetricValue)
		}
	}
}

func TestNTPMonitorQueryServers(t *testing.T) {
	mockNTP := MockNTPClient{}
	failNTP := MockNTPClient{
		ignoredServers: map[string]string{"s1": "", "s2": "", "s3": ""},
	}
	partialFailNTP := MockNTPClient{
		ignoredServers: map[string]string{"s2": "", "s3": ""},
	}

	offsetDuration, err := time.ParseDuration("5s")
	if err != nil {
		t.Fatalf("unexpected failed to parse duration: %v", err)
	}

	driftedNTP := driftedTimeNTPClient{
		driftedOffset: offsetDuration,
	}

	testCases := []struct {
		name                       string
		client                     NTPClient
		serverThreshold            int
		maxTimeDelta               int
		expectEnoughServerResponse bool
		expectValidServerResponse  bool
	}{
		{
			name:                       "Successfully query all NTP servers",
			client:                     mockNTP,
			serverThreshold:            3,
			maxTimeDelta:               3,
			expectEnoughServerResponse: true,
			expectValidServerResponse:  true,
		},
		{
			name:                       "Receive too few server responses",
			client:                     partialFailNTP,
			serverThreshold:            2,
			maxTimeDelta:               5,
			expectEnoughServerResponse: false,
			expectValidServerResponse:  false,
		},
		{
			name:                       "Receive too many drifted time responses",
			client:                     driftedNTP,
			serverThreshold:            2,
			maxTimeDelta:               2,
			expectEnoughServerResponse: true,
			expectValidServerResponse:  false,
		},
		{
			name:                       "Fail to receive any responses",
			client:                     failNTP,
			serverThreshold:            1,
			maxTimeDelta:               4,
			expectEnoughServerResponse: false,
			expectValidServerResponse:  false,
		},
	}
	for _, tc := range testCases {
		monitor, err := NewFromConfigWithClient(&Config{
			Servers:         []string{"s1", "s2", "s3", "s4", "s5", "s6"},
			NumServers:      3,
			Period:          1,
			RequestAttempts: 1,
			RequestTimeout:  1,
			ServerThreshold: tc.serverThreshold,
			MaxTimeDelta:    tc.maxTimeDelta,
		}, tc.client)
		if err != nil {
			t.Fatalf("unexpectedly failed to create NTP monitor: %v", err)
		}

		delta := time.Duration(tc.maxTimeDelta) * time.Second
		testedServers := []string{"s1", "s2", "s3"}

		responses := monitor.queryServers(delta, testedServers)
		if tc.expectEnoughServerResponse && responses.tooFewServerResponses {
			t.Errorf("test '%s' unexpectedly failed with too few server responses", tc.name)
		}
		if tc.expectValidServerResponse && responses.tooManyInvalidResponses {
			t.Errorf("test '%s' unexpectedly failed with too many invalid responses", tc.name)
		}
	}
}
