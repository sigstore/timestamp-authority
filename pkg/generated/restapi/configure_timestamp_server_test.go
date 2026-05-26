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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	pkgapi "github.com/sigstore/timestamp-authority/v2/pkg/api"
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
