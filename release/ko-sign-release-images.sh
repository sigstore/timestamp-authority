#!/usr/bin/env bash

# Copyright 2022 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License"";
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail

: "${GIT_HASH:?Environment variable empty or not defined.}"
: "${GIT_VERSION:?Environment variable empty or not defined.}"

if [[ ! -f timestampServerImagerefs ]]; then
    echo "timestampServerImagerefs not found"
    exit 1
fi

if [[ ! -f timestampCLIImagerefs ]]; then
    echo "timestampCLIImagerefs not found"
    exit 1
fi

echo "Signing images with Keyless..."
readarray -t server_images < <(cat timestampServerImagerefs || true)
cosign sign --yes -a GIT_HASH="${GIT_HASH}" -a GIT_VERSION="${GIT_VERSION}" "${server_images[@]}"
cosign verify --certificate-identity-regexp ".*" --certificate-oidc-issuer-regexp ".*" "${server_images[@]}"

readarray -t cli_images < <(cat timestampCLIImagerefs || true)
cosign sign --yes -a GIT_HASH="${GIT_HASH}" -a GIT_VERSION="${GIT_VERSION}" "${cli_images[@]}"
cosign verify --certificate-identity-regexp ".*" --certificate-oidc-issuer-regexp ".*" "${cli_images[@]}"
