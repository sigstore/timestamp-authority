[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/sigstore/timestamp-authority/badge)](https://api.securityscorecards.dev/projects/github.com/sigstore/timestamp-authority)

# Sigstore Timestamp Authority

A service for issuing [RFC 3161 timestamps](https://datatracker.ietf.org/doc/html/rfc3161).

Timestamps conform to the [RFC 3628 policy](https://datatracker.ietf.org/doc/html/rfc3628).
The timestamp structure conforms to the updates in [RFC 5816](https://datatracker.ietf.org/doc/rfc5816).

## Security model

[Trusted timestamping](https://en.wikipedia.org/wiki/Trusted_timestamping) is a process that has been around for some time.
It provides a timestamp record of when a documented was created or modified.

A timestamp authority creates signed timestamps using public key infrastructure. The operator of the timestamp
authority must secure the signing key material to prevent unauthorized timestamp signing.

A timestamp authority should also verify its own clock. We provide a configuration to periodically check the current
time against well-known NTP sources.

## Timestamping within Sigstore

Timestamps are a critical component of [Rekor](https://github.com/sigstore/rekor), Sigstore's signature transparency log.
Timestamps are used to verify short-lived certificates. Currently, the timestamp comes from Rekor's own internal clock,
which is not externally verifiable or immutable. Using signed timestamps issued from timestamp authorities mitigates the risk of
Rekor's clock being manipulated.

As a artifact signer, you can:

* Generate a signature over an artifact
* Fetch a timestamp for that signature (more below in [What to sign](#what-to-sign))
* Upload the signature, artifact hash, and certificate to Rekor (hashedrekord record type)
* Upload the timestamp to Rekor (rfc3161 record type)
   * This step is important because it makes the timestamps publicly auditable

As an artifact verifier:

* Fetch the artifact entry from Rekor
* If the artifact was signed with a certificate, verify its expiration
   * If you trust Rekor's clock, verify the certificate with the timestamp in the Rekor response
   * If you trust an external timestamp authority, fetch the timestamp from Rekor, verify the
     signed timestamp, and verify the certificate using the signed timestamp

### What to sign

For usage within Sigstore, we recommend signing over a value that is associated with a signature.
For [Cosign](https://github.com/sigstore/cosign/), we have chosen to sign the artifact signature,
a process called "countersigning". We sign over the raw signature bytes, not a base64-encoded value. Signing
over the signature ensures that the signature, not the artifact, was created at a certain time.

## Local development

Prerequisite: On macOS, we currently require the installation of `openssl`. 

```shell
brew install openssl
```

To launch the server, run either:
* `docker-compose up`
* `make timestamp-server && ./bin/timestamp-server serve --port 3000`

Both of these commands launch a server with an in-memory signing key and certificate chain. **This should not
be used for production.**

To fetch a timestamp with the provided `timestamp-cli`:

1. Retrieve the verification chain: `curl http://localhost:3000/api/v1/timestamp/certchain > ts_chain.pem`
1. Create test blob to sign: `echo "myblob" > myblob`
1. Build client: `make timestamp-cli`
1. Fetch timestamp: `./bin/timestamp-cli --timestamp_server http://localhost:3000 timestamp --hash sha256 --artifact myblob --out response.tsr`
1. Verify timestamp: `./bin/timestamp-cli verify --timestamp response.tsr --artifact "myblob" --certificate-chain ts_chain.pem --format json`
1. Inspect timestamp: `./bin/timestamp-cli inspect --timestamp response.tsr --format json`

To fetch a timestamp with `openssl` and `curl`:

1. Retrieve the verification chain: `curl http://localhost:3000/api/v1/timestamp/certchain > ts_chain.pem`
1. Split chain into root CA certificate and "untrusted" intermediate and leaf certificates:
   1. Split: `csplit -s -f tmpcert- ts_chain.pem '/-----BEGIN CERTIFICATE-----/' '{*}'`
      * Note, on macOS, you will need to install GNU utilities with `brew install coreutils`, and use `gcsplit`
   1. Remove empty file: `rm tmpcert-00`
   1. Get root: `mv $(ls tmpcert-* | tail -1) root.crt.pem`
   1. Merge remaining certificates: `cat tmpcert-* > chain.crts.pem`
   1. Remove temp files: `rm tmpcert-*`
1. Create test blob to sign: `echo "myblob" > myblob`
1. Create timestamp request: `openssl ts -query -data myblob -cert -sha256 -out request.tsq`
1. Fetch timestamp: `curl -sSH "Content-Type: application/timestamp-query" --data-binary @request.tsq http://localhost:3000/api/v1/timestamp -o response.tsr`
1. Verify timestamp: `openssl ts -verify -in response.tsr -data "myblob" -CAfile root.crt.pem -untrusted chain.crts.pem`
   * Note that you will see a warning that one certificate is "not a CA cert", but this is expected, as you need to provide the TSA signing certificate
     in case the certificate is not included in the response. When generating the timestamp query, setting `-cert` will mandate the signing certificate
     is included.
1. Inspect timestamp: `openssl ts -reply -in response.tsr -text`

## Production deployment

To deploy to production, the timestamp authority currently supports signing with Cloud KMS or
[Tink](https://github.com/google/tink). You will need to provide
a certificate chain (leaf, any intermediates, and root), where the certificate chain's purpose (extended key usage) is
for timestamping. We do not recommend the file signer for production since the signing key will only be password protected.

### Cloud KMS

Create an asymmetric cloud KMS signing key in either GCP, AWS, Azure, or Vault, that will be used to sign timestamps.

Generate a certificate chain, which must include a leaf certificate whose public key pairs to the private key
in cloud KMS, may include any number of intermediate certificates, and must include a root certificate.
We recommend reviewing the [code](https://github.com/sigstore/timestamp-authority/blob/main/cmd/fetch-tsa-certs/fetch_tsa_certs.go)
used to generate the certificate chain if you do not want to use GCP. If you are using GCP:
* Create a root CA with [GCP CA Service](https://cloud.google.com/certificate-authority-service). Configure lifetime, and other defaults
  can remain. You will need to first create a CA pool, and then create one CA in that pool. 
* Create an asymmetric signing key on KMS that will be used as an intermediate CA to sign the TSA certificate.
* Run the following:

```shell
go run cmd/fetch-tsa-certs/fetch_tsa_certs.go \
  --intermediate-kms-resource="gcpkms://projects/<project>/locations/<region>/keyRings/<key-ring>/cryptoKeys/<key>/versions/1" \
  --leaf-kms-resource="gcpkms://projects/<project>/locations/<region>/keyRings/<leaf-key-ring>/cryptoKeys/<key>/versions/1" \
  --gcp-ca-parent="projects/<project>/locations/<region>/caPools/<ca-pool>" \
  --output="chain.crt.pem"
```

Set `--timestamp-signer=kms`, provide the path to the chain with `--certificate-chain-path`,
and the KMS key with `--kms-key-resource`. The key should be prefixed with either `gcpkms://`, `azurekms://`, `awskms://`, or `hashivault://`.

### Tink

[Tink](https://github.com/google/tink) is an easy-to-use cross-language crypto library.
The timestamp authority provides a signer that uses Tink, which enables in-memory signing
with secure on-disk key storage. Instead of being password-protected, the key is encrypted
with a cloud KMS key, and decrypted on startup.

Install [tinkey](https://github.com/google/tink/blob/master/docs/TINKEY.md) first.

Create a symmetric cloud KMS key in either GCP, AWS, or Vault, that will be used to encrypt a
signing key that is generated locally.

Run the following to create the local encrypted signing key, changing key URI and the key template if desired:

```shell
tinkey create-keyset --key-template ECDSA_P384 --out enc-keyset.cfg --master-key-uri gcp-kms://path-to-key
```

Generate a certificate chain, which must include a leaf certificate whose public key pairs to the private key
in the Tink keyset, may include any number of intermediate certificates, and must include a root certificate.
We recommend reviewing the [code](https://github.com/sigstore/timestamp-authority/blob/main/cmd/fetch-tsa-certs/fetch_tsa_certs.go)
used to generate the certificate chain if you do not want to use GCP. If you are using GCP:
* Create a root CA with [GCP CA Service](https://cloud.google.com/certificate-authority-service). Configure lifetime, and other defaults
  can remain. You will need to first create a CA pool, and then create one CA in that pool. 
* Create an asymmetric signing key on KMS that will be used as an intermediate CA to sign the TSA certificate.
* Run the following:

```shell
go run cmd/fetch-tsa-certs/fetch_tsa_certs.go \
  --intermediate-kms-resource="gcpkms://asymmetric-kms-key"\
  --tink-kms-resource="gcp-kms://tink-encryption-key"\
  --gcp-ca-parent="projects/<project>/locations/<location>/caPools/<pool-name>"\
  --tink-keyset-path="enc-keyset.cfg"\
  --output="chain.crt.pem"
```

To run the TSA, set `--timestamp-signer=tink`, `--tink-key-resource=<path-to-kms-key>`, and
`--tink-keyset-path=enc-keyset.cfg`. The key resource should be prefixed with either `gcp-kms://`, `aws-kms://`, or `hcvault://`.
If using Vault, you may also set `--tink-hcvault-token`. Provide the path to the chain with `--certificate-chain-path`.

## Security

Should you discover any security issues, please refer to Sigstore's [security
process](https://github.com/sigstore/.github/blob/main/SECURITY.md).
