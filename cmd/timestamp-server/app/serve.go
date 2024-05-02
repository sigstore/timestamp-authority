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

package app

import (
	"flag"
	"net/http"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"sigs.k8s.io/release-utils/version"

	"github.com/sigstore/timestamp-authority/pkg/log"
	"github.com/sigstore/timestamp-authority/pkg/ntpmonitor"
	"github.com/sigstore/timestamp-authority/pkg/server"
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "start http server with configured api",
	Long:  `Starts a http server and serves the configured api`,
	Run: func(cmd *cobra.Command, _ []string) {
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			log.Logger.Fatal(err)
		}
		// Setup the logger to dev/prod
		log.ConfigureLogger(viper.GetString("log-type"))

		// workaround for https://github.com/sigstore/rekor/issues/68
		// from https://github.com/golang/glog/commit/fca8c8854093a154ff1eb580aae10276ad6b1b5f
		_ = flag.CommandLine.Parse([]string{})

		vi := version.GetVersionInfo()
		viStr, err := vi.JSONString()
		if err != nil {
			viStr = vi.String()
		}
		log.Logger.Infof("starting timestamp-server @ %v", viStr)

		// create the prometheus, pprof, and rest API servers

		readTimeout := viper.GetDuration("read-timeout")
		writeTimeout := viper.GetDuration("write-timeout")

		go func() {
			promServer := server.NewPrometheusServer(readTimeout, writeTimeout)

			if err := promServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Logger.Fatalf("error when starting or running http server for metrics: %v", err)
			}
		}()

		enablePprof := viper.GetBool("enable-pprof")
		log.Logger.Debugf("pprof enabled: %v", enablePprof)
		// Enable pprof
		if enablePprof {
			go func() {
				pprofServer := server.NewPprofServer(readTimeout, writeTimeout)

				if err := pprofServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					log.Logger.Fatalf("error when starting or running http server for pprof: %v", err)
				}
			}()
		}

		var ntpm *ntpmonitor.NTPMonitor
		disableNTPMonitoring := viper.GetBool("disable-ntp-monitoring")
		if disableNTPMonitoring {
			log.Logger.Info("ntp monitoring disabled")
		} else {
			ntpMonitoring := viper.GetString("ntp-monitoring")
			if ntpMonitoring != "" {
				log.Logger.Infof("using custom ntp monitoring config: %s", ntpMonitoring)
			}

			go func() {
				ntpm, err = ntpmonitor.New(ntpMonitoring)
				if err != nil {
					log.Logger.Fatalf("error initializing ntp monitor %s", err)
				}

				ntpm.Start()
			}()
		}

		host := viper.GetString("host")
		port := int(viper.GetUint("port"))
		scheme := viper.GetStringSlice("scheme")
		server := server.NewRestAPIServer(host, port, scheme, httpPingOnly, readTimeout, writeTimeout)
		defer func() {
			if err := server.Shutdown(); err != nil {
				log.Logger.Error(err)
			}
			if ntpm != nil {
				ntpm.Stop()
			}
		}()
		if err := server.Serve(); err != nil {
			log.Logger.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(version.Version())
}
