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
	"encoding/base64"
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
	ts "github.com/sigstore/timestamp-authority/v2/pkg/generated/restapi/operations/timestamp"
	"github.com/sigstore/timestamp-authority/v2/pkg/verification"
)

type JSONRequest struct {
	ArtifactHash  string   `json:"artifactHash"`
	Certificates  bool     `json:"certificates"`
	HashAlgorithm string   `json:"hashAlgorithm"`
	Nonce         *big.Int `json:"nonce"`
	TSAPolicyOID  string   `json:"tsaPolicyOID"`
}

func getHashAlg(alg string) (crypto.Hash, string, error) {
	lowercaseAlg := strings.ToLower(alg)
	switch lowercaseAlg {
	case "sha256":
		return crypto.SHA256, "", nil
	case "sha384":
		return crypto.SHA384, "", nil
	case "sha512":
		return crypto.SHA512, "", nil
	case "sha1":
		return 0, WeakHashAlgorithmTimestampRequest, verification.ErrWeakHashAlg
	default:
		return 0, failedToGenerateTimestampResponse, fmt.Errorf("unsupported hash algorithm: %s", alg)
	}
}

// ParseJSONRequest parses a JSON request into a timestamp.Request struct
func ParseJSONRequest(reqBytes []byte) (*timestamp.Request, string, error) {
	// unmarshal the request bytes into a JSONRequest struct
	var req JSONRequest
	if err := json.Unmarshal(reqBytes, &req); err != nil {
		return nil, failedToGenerateTimestampResponse, fmt.Errorf("failed to parse JSON into request: %v", err)
	}

	// after unmarshalling, parse the JSONRequest.Artifact into a Reader and parse the remaining
	// fields into a a timestamp.RequestOptions struct
	hashAlgo, errMsg, err := getHashAlg(req.HashAlgorithm)
	if err != nil {
		return nil, errMsg, fmt.Errorf("failed to parse hash algorithm: %v", err)
	}

	var oidInts []int
	if req.TSAPolicyOID == "" {
		oidInts = nil
	} else {
		// 128 is the max number of sub-identifiers per
		// https://datatracker.ietf.org/doc/html/rfc2578#section-3.5
		if c := strings.Count(req.TSAPolicyOID, "."); c > 128 {
			return nil, excesssivelyLongOID, fmt.Errorf("oid has %d sub identifiers, expected 128", c)
		}
		for _, v := range strings.SplitN(req.TSAPolicyOID, ".", 129) {
			i, _ := strconv.Atoi(v)
			oidInts = append(oidInts, i)
		}
	}

	// decode the base64 encoded artifact hash
	decoded, err := base64.StdEncoding.DecodeString(req.ArtifactHash)
	if err != nil {
		return nil, failedToGenerateTimestampResponse, fmt.Errorf("failed to decode base64 encoded artifact hash: %v", err)
	}

	// create a timestamp request from the request's JSON body
	tsReq := timestamp.Request{
		HashAlgorithm: hashAlgo,
		HashedMessage: decoded,
		Certificates:  req.Certificates,
		Nonce:         req.Nonce,
		TSAPolicyOID:  oidInts,
	}

	return verifyTimestampRequest(&tsReq)
}

func parseDERRequest(reqBytes []byte) (*timestamp.Request, string, error) {
	parsed, err := timestamp.ParseRequest(reqBytes)
	if err != nil {
		return nil, failedToGenerateTimestampResponse, err
	}

	return verifyTimestampRequest(parsed)
}

func getContentType(r *http.Request) (string, error) {
	contentTypeHeader := r.Header.Get("Content-Type")
	if strings.Count(contentTypeHeader, "application/") != 1 {
		return "", errors.New("content-type header should specify application only once")
	}
	splitHeader := strings.SplitN(contentTypeHeader, "application/", 2)
	if len(splitHeader) != 2 {
		return "", errors.New("expected header value to be split into two pieces")
	}
	return splitHeader[1], nil
}

func requestBodyToTimestampReq(reqBytes []byte, contentType string) (*timestamp.Request, string, error) {
	switch contentType {
	case "json":
		return ParseJSONRequest(reqBytes)
	case "timestamp-query":
		return parseDERRequest(reqBytes)
	default:
		return nil, failedToGenerateTimestampResponse, fmt.Errorf("unsupported content type")
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

	req, errMsg, err := requestBodyToTimestampReq(requestBytes, contentType)
	if err != nil {
		return handleTimestampAPIError(params, http.StatusBadRequest, err, errMsg)
	}

	policyID := req.TSAPolicyOID
	if policyID.String() == "" {
		policyID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 2}
	}

	duration, _ := time.ParseDuration("1s")

	tsStruct := timestamp.Timestamp{
		HashAlgorithm: req.HashAlgorithm,
		HashedMessage: req.HashedMessage,
		// The field here is going to be serialized as a GeneralizedTime, and RFC5280
		// states that the GeneralizedTime values MUST be expressed in Greenwich Mean Time.
		// However, go asn1/marshal will happily accept other formats. So we force it directly here.
		// https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5.2
		Time:     time.Now().UTC(),
		Nonce:    req.Nonce,
		Policy:   policyID,
		Ordering: false,
		Accuracy: duration,
		// Not qualified for the european directive
		Qualified:         false,
		AddTSACertificate: req.Certificates,
		ExtraExtensions:   req.Extensions,
	}
	if api.includeChain {
		tsStruct.Certificates = api.certChain[1:] // Issuing CA certificate down to root
	}

	resp, err := tsStruct.CreateResponseWithOpts(api.certChain[0], api.tsaSigner, api.tsaSignerHash)
	if err != nil {
		return handleTimestampAPIError(params, http.StatusInternalServerError, err, failedToGenerateTimestampResponse)
	}

	if api.useHTTP201 {
		return ts.NewGetTimestampResponseCreated().WithPayload(io.NopCloser(bytes.NewReader(resp)))
	}
	return ts.NewGetTimestampResponseOK().WithPayload(io.NopCloser(bytes.NewReader(resp)))
}

func GetTimestampCertChainHandler(_ ts.GetTimestampCertChainParams) middleware.Responder {
	return ts.NewGetTimestampCertChainOK().WithPayload(api.certChainPem)
}

func verifyTimestampRequest(tsReq *timestamp.Request) (*timestamp.Request, string, error) {
	if err := verification.VerifyRequest(tsReq); err != nil {
		// verify that the request's hash algorithm is not weak
		if errors.Is(err, verification.ErrWeakHashAlg) {
			return nil, WeakHashAlgorithmTimestampRequest, err
		}
		// verify that the request's hash algorithm is supported
		if errors.Is(err, verification.ErrUnsupportedHashAlg) {
			return nil, failedToGenerateTimestampResponse, err
		}
		// verify that the request's digest length is consistent with the request's hash algorithm
		if errors.Is(err, verification.ErrInconsistentDigestLength) {
			return nil, InconsistentDigestLengthTimestampRequest, err
		}
		return nil, failedToGenerateTimestampResponse, err
	}

	return tsReq, "", nil
}
