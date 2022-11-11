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
	"fmt"
	"sync/atomic"
	"time"

	"github.com/beevik/ntp"

	"github.com/sigstore/timestamp-authority/pkg/log"
)

var (
	// ErrInvTime indicates that the local time has drifted too much
	// from the monitored NTP servers.
	ErrInvTime = errors.New("local time differs from observed")
	// ErrTooFewServers means that the number of trusted servers are
	// smaller then the selected num servers to query.
	ErrTooFewServers = errors.New("too few ntp servers configured")
	// ErrNoResponse indicates that there is an error to communicate with
	// the remote NTP servers
	ErrNoResponse = errors.New("no ntp response")
)

// NTPMonitor compares the local time with a set of trusted NTP servers.
type NTPMonitor struct {
	cfg *Config
	run atomic.Bool
}

// New creates a NTPMonitor, reading the configuration from the provided
// path.
func New(configFile string) (*NTPMonitor, error) {
	cfg, err := LoadConfig(configFile)
	if err != nil {
		return nil, err
	}
	return NewFromConfig(cfg), nil
}

// NewFromConfig creates a NTPMonitor from an instantiated configuration.
func NewFromConfig(cfg *Config) *NTPMonitor {
	return &NTPMonitor{cfg: cfg}
}

// Start the periodic monitor. If there is an initialization error, the
// function returns immediately. Once the periodic monitoring starts, it runs
// until an error is found, or Stop() is being called.
func (n *NTPMonitor) Start() error {
	n.run.Store(true)

	if len(n.cfg.Servers) < n.cfg.NumServers {
		return ErrTooFewServers
	}

	if n.cfg.ServerThreshold > n.cfg.NumServers {
		return ErrTooFewServers
	}

	delta := time.Duration(n.cfg.MaxTimeDelta) * time.Second
	for n.run.Load() {
		// Get a random set of servers
		servers := RandomChoice(n.cfg.Servers, n.cfg.NumServers)
		if len(servers) < 1 {
			// This *should* never happen!
			return ErrTooFewServers
		}

		validResponses := 0
		noResponse := 0
		for _, srv := range servers {
			// Create a time interval from 'now' with the max
			// time delta added/remobed
			// Make sure the time from the remote NTP server lies
			// within this interval.
			resp, err := n.QueryNTPServer(srv)
			now := time.Now()

			if err != nil {
				log.Logger.Warnf("ntp response timeout from %s",
					srv)
				noResponse++
				continue
			}

			if resp.Time.After(now.Add(-delta)) &&
				resp.Time.Before(now.Add(delta)) {
				validResponses++
			} else {
				log.Logger.Warnf("local time is different from %s: %s",
					srv, resp.Time)
			}
		}

		// Did enough NTP servers respond?
		if n.cfg.ServerThreshold > n.cfg.NumServers-noResponse {
			return ErrNoResponse
		}
		if n.cfg.ServerThreshold > validResponses {
			return ErrInvTime
		}

		// Local time is in sync. Wait for next poll.
		time.Sleep(time.Duration(n.cfg.Period) * time.Second)
	}

	return nil
}

// Stop the monitoring.
func (n *NTPMonitor) Stop() {
	n.run.Store(false)
}

// QueryNTPServer queries a provided ntp server, trying up to a configured
// amount of times. There is one second sleep between each attempt.
func (n *NTPMonitor) QueryNTPServer(srv string) (*ntp.Response, error) {
	var i = 1
	for {
		log.Logger.Debugf("querying ntp server %s", srv)
		resp, err := ntp.Query(srv)
		if err == nil {
			return resp, nil
		}
		log.Logger.Infof("ntp timeout from %s, attempt %d/%d",
			srv, i, n.cfg.RequestRetries)
		if i == n.cfg.RequestRetries {
			break
		}
		i++
		time.Sleep(time.Second)
	}
	return nil, fmt.Errorf("ntp timeout: %s", srv)
}
