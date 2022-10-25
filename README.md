# Sigstore Timestamp Authority

A service for issuing [RFC 3161 timestamps](https://datatracker.ietf.org/doc/html/rfc3161).

Timestamps conform to the [RFC 3628 policy](https://datatracker.ietf.org/doc/html/rfc3628).

### Prerequisites

On MacOS, we currently require the installation of `openssl`. 

```shell
brew install openssl
```

## Local development

To launch the server, run either:
* `docker-compose up`
* `go build ./cmd/timestamp-server && ./bin/timestamp-server serve --port 3000`

Both of these commands launch a server with an in-memory signing key and certificate chain. **This should not
be used for production.**

To fetch a timestamp with the provided `timestamp-cli`:

1. Retrieve the verification chain: `curl http://localhost:3000/api/v1/timestamp/certchain > ts_chain.pem`
1. Create test blob to sign: `echo "myblob" > myblob`
1. Build client: `go build ./cmd/timestamp-cli`
1. Fetch timestamp: `./bin/timestamp-cli --timestamp_server http://localhost:3000 timestamp --hash sha256 --artifact myblob --out response.tsr`
1. Verify timestamp: `./bin/timestamp-cli verify --timestamp response.tsr --artifact "myblob" --cert-chain ts_chain.pem`
1. Inspect timestamp: `./bin/timestamp-cli inspect --timestamp response.tsr --format json`

To fetch a timestamp with `openssl` and `curl`:

1. Retrieve the verification chain: `curl http://localhost:3000/api/v1/timestamp/certchain > ts_chain.pem`
1. Create test blob to sign: `echo "myblob" > myblob`
1. Create timestamp request: `openssl ts -query -data myblob -cert -sha256 -out request.tsq`
1. Fetch timestamp: `curl -sSH "Content-Type: application/timestamp-query" --data-binary @request.tsq http://localhost:3000/api/v1/timestamp -o response.tsr`
1. Verify timestamp: `openssl ts -verify -in response.tsr -data "myblob" -CAfile ts_chain.pem`
1. Inspect timestamp: `openssl ts -reply -in response.tsr -text`

## Production deployment

To deploy to production, the timestamp authority currently supports signing with Cloud KMS. You will need to provide
a certificate chain (leaf, any intermediates, and root), where the certificate chain's purpose (extended key usage) is
for timestamping.

Provide the path to the chain with `certificate-chain-path`, and the KMS key with `timestamp-signer`. The key should be prefixed
with either `gcpkms://`, `azurekms://`, `awskms://`, or `hashivault://`.

## Security

Should you discover any security issues, please refer to Sigstore's [security
process](https://github.com/sigstore/.github/blob/main/SECURITY.md).
