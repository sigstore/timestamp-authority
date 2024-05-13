#
# Copyright 2022 The Sigstore Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

.PHONY: all test clean clean-gen lint gosec ko ko-local

all: timestamp-cli timestamp-server

GENSRC = pkg/generated/client/%.go pkg/generated/models/%.go pkg/generated/restapi/%.go
OPENAPIDEPS = openapi.yaml
SRCS = $(shell find cmd -iname "*.go") $(shell find pkg -iname "*.go"|grep -v pkg/generated) pkg/generated/restapi/configure_timestamp_server.go $(GENSRC)
TOOLS_DIR := hack/tools
TOOLS_BIN_DIR := $(abspath $(TOOLS_DIR)/bin)

# Set version variables for LDFLAGS
GIT_VERSION ?= $(shell git describe --tags --always --dirty)
GIT_HASH ?= $(shell git rev-parse HEAD)
DATE_FMT = +%Y-%m-%dT%H:%M:%SZ
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct)
ifdef SOURCE_DATE_EPOCH
    BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u "$(DATE_FMT)")
else
    BUILD_DATE ?= $(shell date "$(DATE_FMT)")
endif
GIT_TREESTATE = "clean"
DIFF = $(shell git diff --quiet >/dev/null 2>&1; if [ $$? -eq 1 ]; then echo "1"; fi)
ifeq ($(DIFF), 1)
    GIT_TREESTATE = "dirty"
endif

KO_PREFIX ?= ghcr.io/cpanato
export KO_DOCKER_REPO=$(KO_PREFIX)

# Binaries
SWAGGER := $(TOOLS_BIN_DIR)/swagger

LDFLAGS=-X sigs.k8s.io/release-utils/version.gitVersion=$(GIT_VERSION) \
				-X sigs.k8s.io/release-utils/version.gitCommit=$(GIT_HASH) \
				-X sigs.k8s.io/release-utils/version.gitTreeState=$(GIT_TREESTATE) \
				-X sigs.k8s.io/release-utils/version.buildDate=$(BUILD_DATE)

CLI_LDFLAGS=$(LDFLAGS)
SERVER_LDFLAGS=$(LDFLAGS)

$(GENSRC): $(SWAGGER) $(OPENAPIDEPS)
	$(SWAGGER) generate client -f openapi.yaml -q -r COPYRIGHT.txt -t pkg/generated
	$(SWAGGER) generate server -f openapi.yaml -q -r COPYRIGHT.txt -t pkg/generated --exclude-main -A timestamp_server --flag-strategy=pflag

.PHONY: validate-openapi
validate-openapi: $(SWAGGER) ## Validate OpenAPI spec
	$(SWAGGER) validate openapi.yaml

# this exists to override pattern match rule above since this file is in the generated directory but should not be treated as generated code
pkg/generated/restapi/configure_timestamp_server.go: $(OPENAPIDEPS)

lint: ## Go linting
	$(GOBIN)/golangci-lint run -v ./...

gosec: ## Run gosec
	$(GOBIN)/gosec ./...

gen: $(GENSRC) ## Generate code from OpenAPI spec

.PHONY : timestamp-cli
timestamp-cli: $(SRCS) ## Build the TSA CLI
	CGO_ENABLED=0 go build -trimpath -ldflags "$(CLI_LDFLAGS)" -o bin/timestamp-cli ./cmd/timestamp-cli

timestamp-server: $(SRCS) ## Build the TSA server 
	CGO_ENABLED=0 go build -trimpath -ldflags "$(SERVER_LDFLAGS)" -o bin/timestamp-server ./cmd/timestamp-server

test: timestamp-cli ## Run tests
	go test ./...

clean: ## Clean all builds
	rm -rf dist
	rm -rf hack/tools/bin
	rm -rf bin/timestamp-cli bin/timestamp-server

clean-gen: clean ## Clean generated code
	rm -rf $(shell find pkg/generated -iname "*.go"|grep -v pkg/generated/restapi/configure_timestamp_server.go)

up: ## Run the TSA with Docker Compose
	docker-compose -f docker-compose.yml build --build-arg SERVER_LDFLAGS="$(SERVER_LDFLAGS)"
	docker-compose -f docker-compose.yml up

ko: ## Run Ko
	# timestamp-server
	LDFLAGS="$(LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	KO_DOCKER_REPO=$(KO_PREFIX)/timestamp-server ko build --bare \
		--platform=all --tags $(GIT_VERSION) --tags $(GIT_HASH) \
		--image-refs timestampServerImagerefs github.com/sigstore/timestamp-authority/cmd/timestamp-server

	# timestamp-cli
	LDFLAGS="$(LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	KO_DOCKER_REPO=$(KO_PREFIX)/timestamp-cli ko build --bare \
		--platform=all --tags $(GIT_VERSION) --tags $(GIT_HASH) \
		--image-refs timestampCLIImagerefs github.com/sigstore/timestamp-authority/cmd/timestamp-cli

.PHONY: ko-local
ko-local: ## Run Ko locally
	LDFLAGS="$(SERVER_LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	ko publish --base-import-paths \
		--tags $(GIT_VERSION) --tags $(GIT_HASH) --local \
		github.com/sigstore/timestamp-authority/cmd/timestamp-server

	LDFLAGS="$(CLI_LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	ko publish --base-import-paths \
		--tags $(GIT_VERSION) --tags $(GIT_HASH) --local \
		github.com/sigstore/timestamp-authority/cmd/timestamp-cli

## --------------------------------------
## Tooling Binaries
## --------------------------------------

$(SWAGGER): $(TOOLS_DIR)/go.mod
	cd $(TOOLS_DIR); go build -trimpath -tags=tools -o $(TOOLS_BIN_DIR)/swagger github.com/go-swagger/go-swagger/cmd/swagger

##################
# help
##################

help: ## Display help
	@awk -F ':|##' \
		'/^[^\t].+?:.*?##/ {\
			printf "\033[36m%-30s\033[0m %s\n", $$1, $$NF \
		}' $(MAKEFILE_LIST) | sort

include release/release.mk
