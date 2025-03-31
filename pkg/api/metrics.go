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

package api

import (
	"math"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"sigs.k8s.io/release-utils/version"
)

var (
	MetricLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "timestamp_authority_api_latency",
		Help: "API Latency on calls",
	}, []string{"path", "code"})

	MetricLatencySummary = promauto.NewSummaryVec(prometheus.SummaryOpts{
		Name: "timestamp_authority_api_latency_summary",
		Help: "API Latency on calls",
	}, []string{"path", "code"})

	MetricRequestLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "timestamp_authority_latency_by_api",
		Help: "API Latency (in ns) by path and method",
		Buckets: prometheus.ExponentialBucketsRange(
			float64(time.Millisecond),
			float64(4*time.Second),
			10),
	}, []string{"path", "method"})

	MetricRequestCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "timestamp_authority_http_requests_total",
		Help: "Total number of HTTP requests by status code, path, and method.",
	}, []string{"code", "path", "method"})

	MetricNTPLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "timestamp_authority_ntp_latency",
		Help: "NTP request latency",
	}, []string{"host"})

	MetricNTPSyncCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "timestamp_authority_ntp_sync_total",
		Help: "Total number of NTP requests against a remote server",
	}, []string{"host", "failed"})

	MetricNTPErrorCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "timestamp_authority_ntp_errors_total",
		Help: "Total number of NTP related errors",
	}, []string{"reason"})

	_ = promauto.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name: "timestamp_authority_certificate_valid_days_remaining",
			Help: "Number of days remaining in validity period of signing certificate",
		},
		func() float64 {
			// if api hasn't been initialized yet, then we can't know the validity period;
			// so we return MaxFloat64 to not cause an alarm if someone fetches the metric
			// before the initialization has completed
			if api == nil {
				return math.MaxFloat64
			}
			// compute minimum validity inclusive of leaf, any intermediates (if present), and root
			minValidity := api.certChain[0].NotAfter
			for _, cert := range api.certChain[1:] {
				if cert.NotAfter.Before(minValidity) {
					minValidity = cert.NotAfter
				}
			}
			return time.Until(minValidity).Hours() / 24
		})

	_ = promauto.NewGaugeFunc(
		prometheus.GaugeOpts{
			Namespace: "timestamp_authority",
			Name:      "build_info",
			Help:      "A metric with a constant '1' value labeled by version, revision, branch, and goversion from which timestamp-authority was built.",
			ConstLabels: prometheus.Labels{
				"version":    version.GetVersionInfo().GitVersion,
				"revision":   version.GetVersionInfo().GitCommit,
				"build_date": version.GetVersionInfo().BuildDate,
				"goversion":  version.GetVersionInfo().GoVersion,
			},
		},
		func() float64 { return 1 },
	)
)
