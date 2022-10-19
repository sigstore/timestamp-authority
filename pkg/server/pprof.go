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

package server

import (
	"net/http"
	"net/http/pprof"
	"time"
)

// NewPprofServer creates a server for handling pprof
func NewPprofServer(readTimeout, writeTimeout time.Duration) *http.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/{action}", pprof.Index)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)

	return &http.Server{
		Addr:         ":6060",
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		Handler:      mux,
	}
}
