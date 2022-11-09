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
