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
	"crypto"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/digitorus/timestamp"
	"github.com/go-openapi/runtime/middleware"
	"github.com/pkg/errors"
	ts "github.com/sigstore/timestamp-authority/pkg/generated/restapi/operations/timestamp"
	"github.com/sigstore/timestamp-authority/pkg/verification"
)

type JSONRequest struct {
	Artifact      string   `json:"artifact"`
	Certificates  bool     `json:"certificates"`
	HashAlgorithm string   `json:"hashAlgorithm"`
	Nonce         *big.Int `json:"nonce"`
	TSAPolicyOID  string   `json:"tsaPolicyOID"`
}

func GetHashAlgo(algo string) (crypto.Hash, error) {
	switch algo {
	case "sha256":
		return crypto.SHA256, nil
	case "sha384":
		return crypto.SHA384, nil
	case "sha512":
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported hash algorithm: %s", algo)
	}
}

func parseJSONRequest(reqBytes []byte) (*timestamp.Request, error) {
	// unmarshal the request bytes into a JSONRequest struct
	var req JSONRequest
	if err := json.Unmarshal(reqBytes, &req); err != nil {
		return nil, fmt.Errorf("failed to parse JSON into request: %v", err)
	}

	// after unmarshalling, parse the JSONRequest.Artifact into a Reader and parse the remaining
	// fields into a a timestamp.RequestOptions struct
	hashAlgo, err := GetHashAlgo(req.HashAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to parse hash algorithm: %v", err)
	}

	var oidInts []int
	if req.TSAPolicyOID == "" {
		oidInts = nil
	} else {
		for _, v := range strings.Split(req.TSAPolicyOID, ".") {
			i, _ := strconv.Atoi(v)
			oidInts = append(oidInts, i)
		}
	}

	opts := timestamp.RequestOptions{
		Certificates: req.Certificates,
		Hash:         hashAlgo,
		Nonce:        req.Nonce,
		TSAPolicyOID: oidInts,
	}

	// create a DER encocded timestamp request from the reader and timestamp.RequestOptions
	tsReqBytes, err := timestamp.CreateRequest(bytes.NewBuffer([]byte(req.Artifact)), &opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create Request from JSON: %v", err)
	}

	// parse the DER encoded timestamp request into a timestamp.Request struct
	tsRequest, err := timestamp.ParseRequest(tsReqBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Request from Request bytes: %v", err)
	}

	return tsRequest, nil
}

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
		return parseJSONRequest(reqBytes)
	case "timestamp-query":
		return timestamp.ParseRequest(reqBytes)
	default:
		return nil, fmt.Errorf("unsupported content type")
	}
}

func TimestampResponseHandler(params ts.GetTimestampResponseParams) middleware.Responder {
	requestBytes, err := io.ReadAll(params.Request)
	if err != nil {
		return handleTimestampAPIError(params, http.StatusBadRequest, err, failedToGenerateTimestampResponse)
	}

	contentType, err := getContentType(params.HTTPRequest)
	if err != nil {
		return handleTimestampAPIError(params, http.StatusUnsupportedMediaType, err, failedToGenerateTimestampResponse)
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
