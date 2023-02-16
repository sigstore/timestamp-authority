package data

import (
	"encoding/asn1"
	"encoding/json"
	"crypto/x509/pkix"
	"math/big"
	"crypto"
	"testing"
	"io"
)

type messageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier `json:"hashAlgorithm"`
	HashedMessage []byte `json:"hashedMessage"`

}

type tsRequest struct {
	Version int `json:"version"`
    MessageImprint messageImprint `json:"messageImprint"`
	ReqPolicy      asn1.ObjectIdentifier `json:"reqPolicy,omitempty"`
	Nonce          *big.Int              `json:"nonce,omitempty"`
	CertReq        bool                  `json:"certReq,omitempty"`
	Extensions     []pkix.Extension      `json:"extensions,omitempty"`
}

func BuildJSONReq(t *testing.T, r io.Reader, inHash crypto.Hash, nonce *big.Int) []byte {
	h := inHash.New()

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
    	CertReq: true,
    	MessageImprint: messageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1},
			},
        	HashedMessage: finished,
    	},
    	Nonce: nonce,
	}

	marshalled, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal request")
	}
	return marshalled
}
