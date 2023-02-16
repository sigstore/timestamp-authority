package tests

import (
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"io"
	"math/big"
	"testing"

	"github.com/digitorus/timestamp"
)

type messageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier `json:"hashAlgorithm"`
	HashedMessage []byte                   `json:"hashedMessage"`
}

type tsRequest struct {
	Version        int                   `json:"version"`
	MessageImprint messageImprint        `json:"messageImprint"`
	ReqPolicy      asn1.ObjectIdentifier `json:"reqPolicy,omitempty"`
	Nonce          *big.Int              `json:"nonce,omitempty"`
	CertReq        bool                  `json:"certReq,omitempty"`
	Extensions     []pkix.Extension      `json:"extensions,omitempty"`
}

type requestOptions struct {
	Nonce        *big.Int
	IncludeCerts bool
	Extensions   []pkix.Extension
	PolicyOID    asn1.ObjectIdentifier
}

func buildJSONReq(t *testing.T, r io.Reader, opts requestOptions) []byte {
	h := crypto.SHA256.New()

	b := make([]byte, h.Size())
	for {
		n, err := r.Read(b)
		if err == io.EOF {
			break
		}

		_, err = h.Write(b[:n])
		if err != nil {
			t.Fatalf("failed to create hash")
		}
	}

	finished := h.Sum(nil)

	req := tsRequest{
		Version: 1,
		CertReq: opts.IncludeCerts,
		MessageImprint: messageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1},
			},
			HashedMessage: finished,
		},
		Nonce:      opts.Nonce,
		Extensions: opts.Extensions,
		ReqPolicy:  opts.PolicyOID,
	}

	marshalled, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal request")
	}
	return marshalled
}

func buildTimestampQueryReq(t *testing.T, r io.Reader, opts requestOptions) []byte {
	tsq, err := timestamp.CreateRequest(r, &timestamp.RequestOptions{
		Hash:         crypto.SHA256,
		Certificates: opts.IncludeCerts,
		Nonce:        opts.Nonce,
		TSAPolicyOID: opts.PolicyOID,
	})
	if err != nil {
		t.Fatalf("unexpected error creating request: %v", err)
	}
	return tsq
}
