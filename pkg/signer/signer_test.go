package signer

import (
	"context"
	"testing"
)

type testcase struct {
	name             string
	signerHashFunc   string
	expectTestToPass bool
}

func TestNewCryptoSignerSignerHashFunc(t *testing.T) {
	testcases := []testcase{{
		name:             "SHA256",
		signerHashFunc:   "sha256",
		expectTestToPass: true,
	},
		{
			name:             "SHA384",
			signerHashFunc:   "sha384",
			expectTestToPass: true,
		},
		{
			name:             "SHA512",
			signerHashFunc:   "sha512",
			expectTestToPass: true,
		},
		{
			name:             "Empty hash func",
			signerHashFunc:   "",
			expectTestToPass: false,
		},
		{
			name:             "Unsupported hash func",
			signerHashFunc:   "sha224",
			expectTestToPass: false,
		}}

	for _, tc := range testcases {
		_, err := NewCryptoSigner(context.Background(), "memory", "", "", "", "", "", "", tc.signerHashFunc)
		if err != nil && tc.expectTestToPass {
			t.Fatalf("test case '%s' failed: %v", tc.name, err)
		}

		if err == nil && !tc.expectTestToPass {
			t.Fatalf("test case '%s' failed: expected error but got nil", tc.name)
		}
	}
}
