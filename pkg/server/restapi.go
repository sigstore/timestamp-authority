package server

import (
	"time"

	"github.com/go-openapi/loads"
	"github.com/sigstore/timestamp-authority/pkg/api"
	"github.com/sigstore/timestamp-authority/pkg/generated/restapi"
	"github.com/sigstore/timestamp-authority/pkg/generated/restapi/operations"
)

// NewRestAPIServer creates a server for serving the rest API TSA service
func NewRestAPIServer(host string, port int, scheme []string, readTimeout, writeTimeout time.Duration) *restapi.Server {
	doc, _ := loads.Embedded(restapi.SwaggerJSON, restapi.FlatSwaggerJSON)
	server := restapi.NewServer(operations.NewTimestampServerAPI(doc))

	server.Host = host
	server.Port = port
	server.EnabledListeners = scheme
	server.ReadTimeout = readTimeout
	server.WriteTimeout = writeTimeout

	api.ConfigureAPI()
	server.ConfigureAPI()

	return server
}
