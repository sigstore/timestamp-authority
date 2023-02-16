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
	"bytes"
	"encoding/asn1"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/digitorus/timestamp"
	"github.com/go-openapi/runtime/middleware"
	"github.com/pkg/errors"
	ts "github.com/sigstore/timestamp-authority/pkg/generated/restapi/operations/timestamp"
	"github.com/sigstore/timestamp-authority/pkg/verification"
)

func getContentType(r *http.Request) (string, error) {
	contentTypeHeader := r.Header.Get("Content-Type")
	splitHeader := strings.Split(contentTypeHeader, "application/")
	if len(splitHeader) != 2 {
		return "", errors.New("expected header value to be split into two pieces")
	}
	return splitHeader[1], nil
}

func requestBodyToTimestampReq(reqBytes []byte, contentType string) (*timestamp.Request, error) {
	switch contentType {
	case "json":
		return timestamp.ParseJSONRequest(reqBytes)
	case "timestamp-query":
		return timestamp.ParseASN1Request(reqBytes)
	default:
		return nil, fmt.Errorf("unsupported content type: %s", contentType)
	}
}

func TimestampResponseHandler(params ts.GetTimestampResponseParams) middleware.Responder {
	requestBytes, err := io.ReadAll(params.Request)
	if err != nil {
		return handleTimestampAPIError(params, http.StatusBadRequest, err, failedToGenerateTimestampResponse)
	}

	contentType, err := getContentType(params.HTTPRequest)
	if err != nil {
		return handleTimestampAPIError(params, http.StatusBadRequest, err, failedToGenerateTimestampResponse)
	}

	req, err := requestBodyToTimestampReq(requestBytes, contentType)
	if err != nil {
		return handleTimestampAPIError(params, http.StatusBadRequest, err, failedToGenerateTimestampResponse)
	}

	if err := verification.VerifyRequest(req); err != nil {
		return handleTimestampAPIError(params, http.StatusBadRequest, err, weakHashAlgorithmTimestampRequest)
	}

	policyID := req.TSAPolicyOID
	if policyID.String() == "" {
		policyID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 2}
	}

	duration, _ := time.ParseDuration("1s")

	tsStruct := timestamp.Timestamp{
		HashAlgorithm: req.HashAlgorithm,
		HashedMessage: req.HashedMessage,
		Time:          time.Now(),
		Nonce:         req.Nonce,
		Policy:        policyID,
		Ordering:      false,
		Accuracy:      duration,
		// Not qualified for the european directive
		Qualified:         false,
		AddTSACertificate: req.Certificates,
		ExtraExtensions:   req.Extensions,
	}

	resp, err := tsStruct.CreateResponse(api.certChain[0], api.tsaSigner)
	if err != nil {
		return handleTimestampAPIError(params, http.StatusInternalServerError, err, failedToGenerateTimestampResponse)
	}

	return ts.NewGetTimestampResponseCreated().WithPayload(io.NopCloser(bytes.NewReader(resp)))
}

func GetTimestampCertChainHandler(params ts.GetTimestampCertChainParams) middleware.Responder {
	return ts.NewGetTimestampCertChainOK().WithPayload(api.certChainPem)
}
