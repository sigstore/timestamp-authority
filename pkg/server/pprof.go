package server

import (
	"net/http"
	"net/http/pprof"
	"time"
)

func NewPprofServer(readTimeout time.Duration, writeTimeout time.Duration) *http.Server {
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
