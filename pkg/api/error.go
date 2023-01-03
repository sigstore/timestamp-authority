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
	"fmt"
	"net/http"
	"regexp"

	"github.com/go-openapi/runtime/middleware"
	"github.com/mitchellh/mapstructure"

	"github.com/sigstore/timestamp-authority/pkg/generated/models"
	"github.com/sigstore/timestamp-authority/pkg/generated/restapi/operations/timestamp"
	"github.com/sigstore/timestamp-authority/pkg/log"
)

const (
	failedToGenerateTimestampResponse = "Error generating timestamp response"
	weakHashAlgorithmTimestampRequest = "Weak hash algorithm in timestamp request"
)

func errorMsg(message string, code int) *models.Error {
	return &models.Error{
		Code:    int64(code),
		Message: message,
	}
}

func handleTimestampAPIError(params interface{}, code int, err error, message string, fields ...interface{}) middleware.Responder {
	if message == "" {
		message = http.StatusText(code)
	}

	re := regexp.MustCompile("^(.*)Params$")
	typeStr := fmt.Sprintf("%T", params)
	handler := re.FindStringSubmatch(typeStr)[1]

	logMsg := func(r *http.Request) {
		log.RequestIDLogger(r).Errorw("exiting with error", append([]interface{}{"handler", handler, "statusCode", code, "clientMessage", message, "error", err}, fields...)...)
		paramsFields := map[string]interface{}{}
		if err := mapstructure.Decode(params, &paramsFields); err == nil {
			log.RequestIDLogger(r).Debug(paramsFields)
		}
	}

	switch params := params.(type) {
	case timestamp.GetTimestampResponseParams:
		logMsg(params.HTTPRequest)
		switch code {
		case http.StatusBadRequest:
			return timestamp.NewGetTimestampResponseBadRequest().WithPayload(errorMsg(message, code))
		case http.StatusNotImplemented:
			return timestamp.NewGetTimestampResponseNotImplemented()
		default:
			return timestamp.NewGetTimestampResponseDefault(code).WithPayload(errorMsg(message, code))
		}
	case timestamp.GetTimestampCertChainParams:
		logMsg(params.HTTPRequest)
		switch code {
		case http.StatusNotFound:
			return timestamp.NewGetTimestampCertChainNotFound()
		default:
			return timestamp.NewGetTimestampCertChainDefault(code).WithPayload(errorMsg(message, code))
		}
	default:
		log.Logger.Errorf("unable to find method for type %T; error: %v", params, err)
		return middleware.Error(http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
	}
}
