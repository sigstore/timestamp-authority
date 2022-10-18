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

	"github.com/go-openapi/loads"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"sigs.k8s.io/release-utils/version"

	"github.com/sigstore/timestamp-authority/pkg/api"
	"github.com/sigstore/timestamp-authority/pkg/generated/restapi"
	"github.com/sigstore/timestamp-authority/pkg/generated/restapi/operations"
	"github.com/sigstore/timestamp-authority/pkg/log"
	tsaserver "github.com/sigstore/timestamp-authority/pkg/server"
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "start http server with configured api",
	Long:  `Starts a http server and serves the configured api`,
	Run: func(cmd *cobra.Command, args []string) {
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

		doc, _ := loads.Embedded(restapi.SwaggerJSON, restapi.FlatSwaggerJSON)
		server := restapi.NewServer(operations.NewTimestampServerAPI(doc))
		defer func() {
			if err := server.Shutdown(); err != nil {
				log.Logger.Error(err)
			}
		}()

		server.Host = viper.GetString("host")
		server.Port = int(viper.GetUint("port"))
		server.EnabledListeners = viper.GetStringSlice("scheme")
		server.ReadTimeout = viper.GetDuration("read-timeout")
		server.WriteTimeout = viper.GetDuration("write-timeout")

		api.ConfigureAPI()
		server.ConfigureAPI()

		http.Handle("/metrics", promhttp.Handler())
		go func() {
			readTimeout = viper.GetDuration("read-timeout")
			writeTimeout = viper.GetDuration("write-timeout")
			srv := &http.Server{
				Addr:         ":2112",
				ReadTimeout:  readTimeout,
				WriteTimeout: writeTimeout,
			}

			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Logger.Fatalf("error when starting or running http server for metrics: %v", err)
			}
		}()

		enablePprof := viper.GetBool("enable-pprof")
		log.Logger.Debugf("pprof enabled: %v", enablePprof)
		// Enable pprof
		if enablePprof {
			go func() {
				readTimeout = viper.GetDuration("read-timeout")
				writeTimeout = viper.GetDuration("write-timeout")

				srv := tsaserver.NewPprofServer(readTimeout, writeTimeout)

				if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					log.Logger.Fatalf("error when starting or running http server for pprof: %v", err)
				}
			}()
		}

		if err := server.Serve(); err != nil {
			log.Logger.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(version.Version())
}
