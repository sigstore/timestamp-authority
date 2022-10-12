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
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	MetricLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "timestamp_api_latency",
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
)
