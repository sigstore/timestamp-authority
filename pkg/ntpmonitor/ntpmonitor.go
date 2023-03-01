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
	"math/rand"
	"sync/atomic"
	"time"

	"github.com/beevik/ntp"

	pkgapi "github.com/sigstore/timestamp-authority/pkg/api"
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
	// ErrThreshold means that there is no positive threshold value
	ErrThreshold = errors.New("no valid server threshold set")
	// ErrDeltaTooSmall is referring to when the max delta time is
	// smaller than the request timeout which can give unstable behaviour.
	ErrDeltaTooSmall = errors.New("delta is too small")
)

type serverResponses struct {
	tooFewServerResponses   bool
	tooManyInvalidResponses bool
}

type NTPClient interface {
	QueryWithOptions(srv string, opts ntp.QueryOptions) (*ntp.Response, error)
}

type LiveNTPClient struct{}

func (c LiveNTPClient) QueryWithOptions(srv string, opts ntp.QueryOptions) (*ntp.Response, error) {
	return ntp.QueryWithOptions(srv, opts)
}

// NTPMonitor compares the local time with a set of trusted NTP servers.
type NTPMonitor struct {
	cfg       *Config
	run       atomic.Bool
	ntpClient NTPClient
}

// New creates a NTPMonitor, reading the configuration from the provided
// path.
func New(configFile string) (*NTPMonitor, error) {
	cfg, err := LoadConfig(configFile)
	if err != nil {
		return nil, err
	}
	return NewFromConfig(cfg)
}

// NewFromConfig creates a NTPMonitor from an instantiated configuration.
func NewFromConfig(cfg *Config) (*NTPMonitor, error) {
	// default to using a live NTP client
	liveNTPClient := LiveNTPClient{}
	return NewFromConfigWithClient(cfg, liveNTPClient)
}

func NewFromConfigWithClient(cfg *Config, client NTPClient) (*NTPMonitor, error) {
	if len(cfg.Servers) == 0 || len(cfg.Servers) < cfg.NumServers {
		return nil, ErrTooFewServers
	}

	if cfg.ServerThreshold < 1 {
		return nil, ErrThreshold
	}

	if cfg.ServerThreshold > cfg.NumServers {
		return nil, ErrTooFewServers
	}

	if cfg.RequestTimeout < 1 || cfg.MaxTimeDelta < cfg.RequestTimeout {
		return nil, ErrDeltaTooSmall
	}

	return &NTPMonitor{cfg: cfg, ntpClient: client}, nil
}

func (n *NTPMonitor) queryServers(delta time.Duration, servers []string) serverResponses {
	validResponses := 0
	noResponse := 0
	for _, srv := range servers {
		// Create a time interval from 'now' with the max
		// time delta added/removed
		// Make sure the time from the remote NTP server lies
		// within this interval.
		resp, err := n.queryNTPServer(srv)
		if err != nil {
			log.Logger.Errorf("ntp response timeout from %s",
				srv)
			noResponse++
			continue
		}

		// ClockOffset is the estimated difference from
		// local time to NTP server's time.
		// The estimate assumes latency is similar for both
		// sending and receiving data.
		// The estimated offset does not depend on the value
		// of the latency.
		if resp.ClockOffset.Abs() > delta {
			log.Logger.Warnf("local time is different from %s: %s",
				srv, resp.Time)
		} else {
			validResponses++
		}
	}

	// Did enough NTP servers respond?
	return serverResponses{
		tooFewServerResponses:   n.cfg.ServerThreshold > n.cfg.NumServers-noResponse,
		tooManyInvalidResponses: n.cfg.ServerThreshold > validResponses,
	}
}

// Start the periodic monitor. Once started, it runs until Stop() is called,
func (n *NTPMonitor) Start() {
	n.run.Store(true)

	if n.cfg.RequestTimeout < 1 {
		log.Logger.Warnf("NTP request timeout not set, default to 1s")
		n.cfg.RequestTimeout = 1
	}

	delta := time.Duration(n.cfg.MaxTimeDelta) * time.Second
	log.Logger.Info("ntp monitoring starting")

	//nolint:gosec
	r := rand.New(rand.NewSource(time.Now().UTC().UnixNano())) // initialize local pseudorandom generator //nolint:gosec

	for n.run.Load() {
		servers := RandomChoice(n.cfg.Servers, n.cfg.NumServers, r)
		responses := n.queryServers(delta, servers)

		// Did enough NTP servers respond?
		if responses.tooFewServerResponses {
			pkgapi.MetricNTPErrorCount.With(map[string]string{
				"reason": "err_too_few",
			}).Inc()
		}
		if responses.tooManyInvalidResponses {
			pkgapi.MetricNTPErrorCount.With(map[string]string{
				"reason": "err_inv_time",
			}).Inc()
		}

		// Local time is in sync. Wait for next poll.
		time.Sleep(time.Duration(n.cfg.Period) * time.Second)
	}
	log.Logger.Info("ntp monitoring stopped")
}

// Stop the monitoring.
func (n *NTPMonitor) Stop() {
	log.Logger.Info("stopping ntp monitoring")
	n.run.Store(false)
}

// queryNTPServer queries a provided ntp server, trying up to a configured
// amount of times. There is one second sleep between each attempt.
func (n *NTPMonitor) queryNTPServer(srv string) (*ntp.Response, error) {
	var i = 1
	for {
		log.Logger.Debugf("querying ntp server %s", srv)

		start := time.Now()
		opts := ntp.QueryOptions{
			Timeout: time.Duration(n.cfg.RequestTimeout) * time.Second,
		}
		resp, err := n.ntpClient.QueryWithOptions(srv, opts)
		pkgapi.MetricNTPLatency.With(map[string]string{
			"host": srv,
		}).Observe(float64(time.Since(start)))
		if err == nil {
			pkgapi.MetricNTPSyncCount.With(map[string]string{
				"failed": "false",
				"host":   srv,
			}).Inc()

			return resp, nil
		}
		pkgapi.MetricNTPSyncCount.With(map[string]string{
			"failed": "true",
			"host":   srv,
		}).Inc()

		log.Logger.Infof("ntp timeout from %s, attempt %d/%d",
			srv, i, n.cfg.RequestAttempts)
		if i == n.cfg.RequestAttempts {
			break
		}
		i++
		time.Sleep(time.Second)
	}
	return nil, fmt.Errorf("ntp timeout: %s", srv)
}
