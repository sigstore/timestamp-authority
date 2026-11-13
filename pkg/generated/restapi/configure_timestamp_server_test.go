// Copyright 2026 The Sigstore Authors.
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

package restapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/testutil"
	pkgapi "github.com/sigstore/timestamp-authority/v2/pkg/api"
	"github.com/sigstore/timestamp-authority/v2/pkg/log"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestWrapMetrics(t *testing.T) {
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := wrapMetrics(dummyHandler)

	tests := []struct {
		name           string
		path           string
		method         string
		expectedPath   string
		expectedMethod string
	}{
		{
			name:           "Valid ping route GET",
			path:           "/ping",
			method:         "GET",
			expectedPath:   "/ping",
			expectedMethod: "GET",
		},
		{
			name:           "Valid timestamp route POST",
			path:           "/api/v1/timestamp",
			method:         "POST",
			expectedPath:   "/api/v1/timestamp",
			expectedMethod: "POST",
		},
		{
			name:           "Valid certchain route GET",
			path:           "/api/v1/timestamp/certchain",
			method:         "GET",
			expectedPath:   "/api/v1/timestamp/certchain",
			expectedMethod: "GET",
		},
		{
			name:           "Unrecognized route GET",
			path:           "/invalid/route",
			method:         "GET",
			expectedPath:   "unrecognized",
			expectedMethod: "GET",
		},
		{
			name:           "Unrecognized route with valid suffix",
			path:           "/api/v1/timestamp/extra",
			method:         "GET",
			expectedPath:   "unrecognized",
			expectedMethod: "GET",
		},
		{
			name:           "Unrecognized route with trailing slash",
			path:           "/api/v1/timestamp/",
			method:         "POST",
			expectedPath:   "unrecognized",
			expectedMethod: "POST",
		},
		{
			name:           "Unrecognized HTTP Method",
			path:           "/api/v1/timestamp",
			method:         "CUSTOM_METHOD",
			expectedPath:   "/api/v1/timestamp",
			expectedMethod: "unrecognized",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset metrics before each subtest to isolate counts
			pkgapi.MetricRequestCount.Reset()

			req := httptest.NewRequest(tt.method, tt.path, nil)
			rr := httptest.NewRecorder()

			wrapped.ServeHTTP(rr, req)

			count := testutil.ToFloat64(pkgapi.MetricRequestCount.With(map[string]string{
				"path":   tt.expectedPath,
				"method": tt.expectedMethod,
				"code":   "200",
			}))

			if count != 1 {
				t.Errorf("expected metric request count to be 1, got %f for labels path=%q, method=%q, code=200", count, tt.expectedPath, tt.expectedMethod)
			}
		})
	}
}

func TestStructuredLogFormatter(t *testing.T) {
	origLogger := log.Logger
	t.Cleanup(func() {
		log.Logger = origLogger
	})

	var buf bytes.Buffer
	encCfg := zap.NewProductionEncoderConfig()
	encCfg.LevelKey = "severity"
	encCfg.MessageKey = "message"
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encCfg),
		zapcore.AddSync(&buf),
		zapcore.DebugLevel,
	)
	log.Logger = zap.New(core).Sugar()

	handler := setupGlobalMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("hello"))
	}))

	req := httptest.NewRequest(http.MethodPost, "http://timestamp.sigstore.dev/api/v1/timestamp", strings.NewReader("payload"))
	req.Header.Set("User-Agent", "test-agent/1.0")
	req.Header.Set(middleware.RequestIDHeader, "baedc1920528a259e488730e20a023dd/4290707823533815095")
	req.RemoteAddr = "35.191.17.116:52968"
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	var entry map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		var candidate map[string]any
		if err := json.Unmarshal([]byte(line), &candidate); err != nil {
			t.Fatalf("failed to unmarshal log line %q: %v", line, err)
		}
		if candidate["message"] == "completed request" {
			entry = candidate
			break
		}
	}
	if entry == nil {
		t.Fatalf("expected 'completed request' log entry in %q", buf.String())
	}

	if got := entry["message"]; got != "completed request" {
		t.Errorf("expected message %q, got %v", "completed request", got)
	}

	op, ok := entry["operation"].(map[string]any)
	if !ok {
		t.Fatalf("expected operation object, got %T (%v)", entry["operation"], entry["operation"])
	}
	if got := op["id"]; got != "baedc1920528a259e488730e20a023dd/4290707823533815095" {
		t.Errorf("expected operation.id %q, got %v", "baedc1920528a259e488730e20a023dd/4290707823533815095", got)
	}

	httpReq, ok := entry["httpRequest"].(map[string]any)
	if !ok {
		t.Fatalf("expected httpRequest object, got %T (%v)", entry["httpRequest"], entry["httpRequest"])
	}
	checks := map[string]any{
		"requestMethod": "POST",
		"requestUrl":    "http://timestamp.sigstore.dev/api/v1/timestamp",
		"requestSize":   "7",
		"status":        float64(http.StatusCreated),
		"responseSize":  "5",
		"userAgent":     "test-agent/1.0",
		"remoteIp":      "35.191.17.116:52968",
		"protocol":      "HTTP/1.1",
	}
	for k, want := range checks {
		if got := httpReq[k]; got != want {
			t.Errorf("httpRequest.%s = %v (%T), want %v (%T)", k, got, got, want, want)
		}
	}
	latency, ok := httpReq["latency"].(string)
	if !ok || !strings.HasSuffix(latency, "s") {
		t.Errorf("expected latency string ending in 's', got %v", httpReq["latency"])
	}
}
