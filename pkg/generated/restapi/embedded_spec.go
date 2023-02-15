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

package restapi

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
)

var (
	// SwaggerJSON embedded version of the swagger document used at generation time
	SwaggerJSON json.RawMessage
	// FlatSwaggerJSON embedded flattened version of the swagger document used at generation time
	FlatSwaggerJSON json.RawMessage
)

func init() {
	SwaggerJSON = json.RawMessage([]byte(`{
  "schemes": [
    "http"
  ],
  "swagger": "2.0",
  "info": {
    "description": "Timestamp Authority provides an RFC3161 timestamp authority.",
    "title": "Timestamp Authority",
    "version": "0.0.1"
  },
  "host": "timestamp.sigstore.dev",
  "paths": {
    "/api/v1/timestamp": {
      "post": {
        "consumes": [
          "application/json",
          "application/timestamp-query"
        ],
        "produces": [
          "application/timestamp-reply"
        ],
        "tags": [
          "timestamp"
        ],
        "summary": "Generates a new timestamp response and creates a new log entry for the timestamp in the transparency log",
        "operationId": "getTimestampResponse",
        "parameters": [
          {
            "name": "request",
            "in": "body",
            "required": true,
            "schema": {
              "type": "string",
              "format": "binary"
            }
          }
        ],
        "responses": {
          "201": {
            "description": "Returns a timestamp response and the location of the log entry in the transprency log",
            "schema": {
              "type": "string",
              "format": "binary"
            }
          },
          "400": {
            "$ref": "#/responses/BadContent"
          },
          "501": {
            "$ref": "#/responses/NotImplemented"
          },
          "default": {
            "$ref": "#/responses/InternalServerError"
          }
        }
      }
    },
    "/api/v1/timestamp/certchain": {
      "get": {
        "description": "Returns the certficate chain for timestamping that can be used to validate trusted timestamps",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/pem-certificate-chain"
        ],
        "tags": [
          "timestamp"
        ],
        "summary": "Retrieve the certficate chain for timestamping that can be used to validate trusted timestamps",
        "operationId": "getTimestampCertChain",
        "responses": {
          "200": {
            "description": "The PEM encoded cert chain",
            "schema": {
              "type": "string"
            }
          },
          "404": {
            "$ref": "#/responses/NotFound"
          },
          "default": {
            "$ref": "#/responses/InternalServerError"
          }
        }
      }
    }
  },
  "definitions": {
    "Error": {
      "type": "object",
      "properties": {
        "code": {
          "type": "integer"
        },
        "message": {
          "type": "string"
        }
      }
    }
  },
  "responses": {
    "BadContent": {
      "description": "The content supplied to the server was invalid",
      "schema": {
        "$ref": "#/definitions/Error"
      }
    },
    "InternalServerError": {
      "description": "There was an internal error in the server while processing the request",
      "schema": {
        "$ref": "#/definitions/Error"
      }
    },
    "NotFound": {
      "description": "The content requested could not be found"
    },
    "NotImplemented": {
      "description": "The content requested is not implemented"
    }
  }
}`))
	FlatSwaggerJSON = json.RawMessage([]byte(`{
  "schemes": [
    "http"
  ],
  "swagger": "2.0",
  "info": {
    "description": "Timestamp Authority provides an RFC3161 timestamp authority.",
    "title": "Timestamp Authority",
    "version": "0.0.1"
  },
  "host": "timestamp.sigstore.dev",
  "paths": {
    "/api/v1/timestamp": {
      "post": {
        "consumes": [
          "application/json",
          "application/timestamp-query"
        ],
        "produces": [
          "application/timestamp-reply"
        ],
        "tags": [
          "timestamp"
        ],
        "summary": "Generates a new timestamp response and creates a new log entry for the timestamp in the transparency log",
        "operationId": "getTimestampResponse",
        "parameters": [
          {
            "name": "request",
            "in": "body",
            "required": true,
            "schema": {
              "type": "string",
              "format": "binary"
            }
          }
        ],
        "responses": {
          "201": {
            "description": "Returns a timestamp response and the location of the log entry in the transprency log",
            "schema": {
              "type": "string",
              "format": "binary"
            }
          },
          "400": {
            "description": "The content supplied to the server was invalid",
            "schema": {
              "$ref": "#/definitions/Error"
            }
          },
          "501": {
            "description": "The content requested is not implemented"
          },
          "default": {
            "description": "There was an internal error in the server while processing the request",
            "schema": {
              "$ref": "#/definitions/Error"
            }
          }
        }
      }
    },
    "/api/v1/timestamp/certchain": {
      "get": {
        "description": "Returns the certficate chain for timestamping that can be used to validate trusted timestamps",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/pem-certificate-chain"
        ],
        "tags": [
          "timestamp"
        ],
        "summary": "Retrieve the certficate chain for timestamping that can be used to validate trusted timestamps",
        "operationId": "getTimestampCertChain",
        "responses": {
          "200": {
            "description": "The PEM encoded cert chain",
            "schema": {
              "type": "string"
            }
          },
          "404": {
            "description": "The content requested could not be found"
          },
          "default": {
            "description": "There was an internal error in the server while processing the request",
            "schema": {
              "$ref": "#/definitions/Error"
            }
          }
        }
      }
    }
  },
  "definitions": {
    "Error": {
      "type": "object",
      "properties": {
        "code": {
          "type": "integer"
        },
        "message": {
          "type": "string"
        }
      }
    }
  },
  "responses": {
    "BadContent": {
      "description": "The content supplied to the server was invalid",
      "schema": {
        "$ref": "#/definitions/Error"
      }
    },
    "InternalServerError": {
      "description": "There was an internal error in the server while processing the request",
      "schema": {
        "$ref": "#/definitions/Error"
      }
    },
    "NotFound": {
      "description": "The content requested could not be found"
    },
    "NotImplemented": {
      "description": "The content requested is not implemented"
    }
  }
}`))
}
