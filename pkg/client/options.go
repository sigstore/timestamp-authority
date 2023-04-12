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

package client

import "net/http"

const (
	TimestampQueryMediaType = "application/timestamp-query"
	JSONMediaType           = "application/json"
)

// Option is a functional option for customizing static signatures.
type Option func(*options)

type options struct {
	UserAgent   string
	ContentType string
}

func makeOptions(opts ...Option) *options {
	o := &options{
		UserAgent:   "",
		ContentType: "",
	}

	for _, opt := range opts {
		opt(o)
	}

	return o
}

// WithUserAgent sets the media type of the signature.
func WithUserAgent(userAgent string) Option {
	return func(o *options) {
		o.UserAgent = userAgent
	}
}

// WithContentType sets the content type of the request.
func WithContentType(contentType string) Option {
	return func(o *options) {
		o.ContentType = contentType
	}
}

type roundTripper struct {
	http.RoundTripper
	UserAgent   string
	ContentType string
}

// RoundTrip implements `http.RoundTripper`
func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", rt.UserAgent)
	req.Header.Set("Content-Type", rt.ContentType)
	return rt.RoundTripper.RoundTrip(req)
}

func createRoundTripper(inner http.RoundTripper, o *options) http.RoundTripper {
	if inner == nil {
		inner = http.DefaultTransport
	}
	if o.UserAgent == "" {
		// There's nothing to do...
		return inner
	}
	if o.ContentType == "" {
		// There's nothing to do...
		return inner
	}
	return &roundTripper{
		RoundTripper: inner,
		UserAgent:    o.UserAgent,
		ContentType:  o.ContentType,
	}
}
