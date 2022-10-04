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
	"io"
	"net/http"
	"time"

	"github.com/go-openapi/runtime/middleware"
	"github.com/haydentherapper/timestamp"
	ts "github.com/sigstore/timestamp-authority/pkg/generated/restapi/operations/timestamp"
)

func TimestampResponseHandler(params ts.GetTimestampResponseParams) middleware.Responder {
	requestBytes, err := io.ReadAll(params.Request)
	if err != nil {
		return handleTimestampAPIError(params, http.StatusBadRequest, err, failedToGenerateTimestampResponse)
	}

	req, err := timestamp.ParseRequest(requestBytes)
	if err != nil {
		return handleTimestampAPIError(params, http.StatusBadRequest, err, failedToGenerateTimestampResponse)
	}

	policyID := req.TSAPolicyOID
	if policyID.String() == "" {
		// https://datatracker.ietf.org/doc/html/rfc3628#section-5.2
		policyID = asn1.ObjectIdentifier{0, 4, 0, 2023, 1, 1}
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
		ExtraExtensions:   req.ExtraExtensions,
		Certificates:      api.certChain,
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
