package server

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// NewPrometheusServer creates a server for serving prometheus metrics
func NewPrometheusServer(readTimeout, writeTimeout time.Duration) *http.Server {
	return &http.Server{
		Addr:         ":2112",
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		Handler:      promhttp.Handler(),
	}
}
