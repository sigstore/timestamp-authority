// Code generated by go-swagger; DO NOT EDIT.

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
//

package timestamp

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new timestamp API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for timestamp API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	GetTimestampCertChain(params *GetTimestampCertChainParams, opts ...ClientOption) (*GetTimestampCertChainOK, error)

	GetTimestampResponse(params *GetTimestampResponseParams, writer io.Writer, opts ...ClientOption) (*GetTimestampResponseCreated, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
GetTimestampCertChain retrieves the certficate chain for timestamping that can be used to validate trusted timestamps

Returns the certficate chain for timestamping that can be used to validate trusted timestamps
*/
func (a *Client) GetTimestampCertChain(params *GetTimestampCertChainParams, opts ...ClientOption) (*GetTimestampCertChainOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetTimestampCertChainParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getTimestampCertChain",
		Method:             "GET",
		PathPattern:        "/api/v1/timestamp/certchain",
		ProducesMediaTypes: []string{"application/pem-certificate-chain"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &GetTimestampCertChainReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetTimestampCertChainOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*GetTimestampCertChainDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
GetTimestampResponse generates a new timestamp response and creates a new log entry for the timestamp in the transparency log
*/
func (a *Client) GetTimestampResponse(params *GetTimestampResponseParams, writer io.Writer, opts ...ClientOption) (*GetTimestampResponseCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetTimestampResponseParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getTimestampResponse",
		Method:             "POST",
		PathPattern:        "/api/v1/timestamp",
		ProducesMediaTypes: []string{"application/json", "application/timestamp-reply"},
		ConsumesMediaTypes: []string{"application/json", "application/timestamp-query"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &GetTimestampResponseReader{formats: a.formats, writer: writer},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetTimestampResponseCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*GetTimestampResponseDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
