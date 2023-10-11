# v1.2.0

v1.2.0 is based on Go 1.21.3.

## Changes

### Enhancements

* Support other hash algs for pre-signed timestamp besides SHA256 (#488)
* new http-ping-only flag for 'timestamp-server serve' (#474)

### Bug Fixes

* Fix bug where TSA signing fails if cert hash != content hash. (#465)

### Misc

* expand README on Cloud KMS deployment (#476)
* upgrade to Go1.21 (#471)

## Contributors

* Billy Lynch
* Carlos Tadeu Panato Junior
* Dmitry Savintsev
* Hayden B

# 1.1.2

1.1.2 fixes a signing related hash function bug and a typo.

## Changes

### Enhancements

### Bug Fixes

* Fix hash function hardcoding bug by updating dependency (https://github.com/sigstore/timestamp-authority/pull/452)

### Misc

* Fix typo in OpenAPI spec (https://github.com/sigstore/timestamp-authority/pull/419)
* Update GoReleaser flag (https://github.com/sigstore/timestamp-authority/pull/356)

## Contributors

* Carlos Tadeu Panato Junior
* Dmitry Savintsev
* Meredith Lancaster

# 1.1.1

1.1.1 fixes a bug in the JSON format request code.

## Changes

### Enhancements

### Bug Fixes

* Update how the JSON body is parsed (https://github.com/sigstore/timestamp-authority/pull/343)

### Misc

## Contributors

* Meredith Lancaster

# 1.1.0

1.1.0 now supports making timestamp requests in JSON format in addition to DER encoded format.

## Changes

### Enhancements

* Support timestamp requests in JSON format (https://github.com/sigstore/timestamp-authority/pull/247)

### Bug Fixes

### Misc

* Fix typo in README (https://github.com/sigstore/timestamp-authority/pull/294)

## Contributors

* Andrea Cosentino
* Meredith Lancaster

# 1.0.0

1.0 release of the timestamp authority. No changes from the previous release candidate.

Thank you to all contributors!

# 1.0.0-rc.1

_Note: This is a prerelease for 1.0. Please try it out and file issues!_

## Changes

* Upgrade to go 1.20.1 (https://github.com/sigstore/timestamp-authority/pull/245)

### Documentation

* Update policy (https://github.com/sigstore/timestamp-authority/pull/251, https://github.com/sigstore/timestamp-authority/pull/262)

## Contributors

* Carlos Tadeu Panato Junior
* Hayden B
* Meredith Lancaster

# 1.0.0-rc.0

_Note: This is a prerelease for 1.0. Please try it out and file issues!_

## Changes

SLSA provenance is now uploaded with each release. Use
[slsa-verifier](https://github.com/slsa-framework/slsa-verifier/) to verify
the release.

### Misc

* Mock NTP client (https://github.com/sigstore/timestamp-authority/pull/217)

## Contributors

* Carlos Tadeu Panato Junior
* Hayden B
* Meredith Lancaster

# 0.2.1

0.2.1 now rejects timestamp requests that use SHA-1. For server operators, it
now defaults to using NTP monitoring.

## Changes

### Enhancements

* Generate slsa provenance (https://github.com/sigstore/timestamp-authority/pull/193)
* Use default NTP monitoring configuration (https://github.com/sigstore/timestamp-authority/pull/186)
* Reject requests that use SHA-1 (https://github.com/sigstore/timestamp-authority/pull/202)

### Bug Fixes

### Misc

* Update README with more details (https://github.com/sigstore/timestamp-authority/pull/188)

## Contributors

* Hayden B
* Hector Fernandez
* Meredith Lancaster

# 0.2.0

0.2.0 improves the verification library (https://github.com/sigstore/timestamp-authority/issues/121).
The library now verifies the full certificate chain and additional properties of the timestamp.

## Changes

### Enhancements

* Start adding more verification with VerificationOpts struct (https://github.com/sigstore/timestamp-authority/pull/153)
* Verify command returns the parsed timestamp (https://github.com/sigstore/timestamp-authority/pull/174)
* Add intermediate and root verify flags (https://github.com/sigstore/timestamp-authority/pull/180)
* Verify full certificate chain (https://github.com/sigstore/timestamp-authority/pull/181)

### Bug fixes

### Misc

* Add mock client (https://github.com/sigstore/timestamp-authority/pull/175)
* Update timing accuracy statements in the policy document (https://github.com/sigstore/timestamp-authority/pull/179)

## Contributors

* Hayden Blauzvern
* Meredith Lancaster

# 0.1.3

## Changes

### Enhancements

* Added an optional feature to compare the local time with a set of trusted ntp servers (https://github.com/sigstore/timestamp-authority/pull/143)

### Bug fixes

* Register KMS providers
  (https://github.com/sigstore/timestamp-authority/pull/160)
* Added .PHONY target for CLI rebuilding (https://github.com/sigstore/timestamp-authority/pull/159)

### Misc

* inspect: remove format flag (https://github.com/sigstore/timestamp-authority/pull/155)

## Contributors

* Fredrik Skogman
* Hector Fernandez
* Meredith Lancaster
* neilnaveen

# 0.1.2

## Changes

### Enhancements

### Bug fixes

* Fix a bug where certChain was not set correctly (https://github.com/sigstore/timestamp-authority/pull/140)

### Misc

## Contributors

* Ville Aikas

# 0.1.1

## Changes

### Enhancements

* Update in memory signer to use intermediate certificate (https://github.com/sigstore/timestamp-authority/pull/136)
* Move verify logic to pkg (https://github.com/sigstore/timestamp-authority/pull/120)

### Bug fixes

* Require the file signer to specify the certificate chain (https://github.com/sigstore/timestamp-authority/pull/137)
* Fix hashed message verification (https://github.com/sigstore/timestamp-authority/pull/118)
* Update fetch TSA certs script for Tink (https://github.com/sigstore/timestamp-authority/pull/111)

### Misc

## Contributors

* Hayden Blauzvern
* Hector Fernandez

# 0.1.0

Initial release of sigstore/timestamp-authority

See the [README](README.md) for instructions on how to run the timestamp authority
and fetch and verify signed timestamps.

## Contributors

* Carlos Tadeu Panato Junior (@cpanato)
* Hayden Blauzvern (@haydentherapper)
* Hector Fernandez (@hectorj2f)
* Meredith Lancaster (@malancas)
