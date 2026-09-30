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

# Debian 13 (Trixie) image to build binary for distroless/static-debian13
FROM --platform=$BUILDPLATFORM golang:1.27.1-trixie@sha256:433790e515d27dc6003e847e644cc0af956985cf315c1c58a3b73ee2dd305183 AS builder
ARG TARGETOS
ARG TARGETARCH
ENV APP_ROOT=/opt/app-root
ENV GOPATH=$APP_ROOT

WORKDIR $APP_ROOT/src/
ADD go.mod go.sum $APP_ROOT/src/
RUN go mod download

# Add source code
ADD ./cmd/ $APP_ROOT/src/cmd/
ADD ./pkg/ $APP_ROOT/src/pkg/

ARG SERVER_LDFLAGS
# Build server for deployment
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} CGO_ENABLED=0 go build -ldflags "${SERVER_LDFLAGS}" -o timestamp-server ./cmd/timestamp-server

# Production deployment build
FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3 AS deploy
# Retrieve the binary from the previous stage
COPY --from=builder /opt/app-root/src/timestamp-server /usr/local/bin/timestamp-server
# Set the binary as the entrypoint of the container
CMD ["timestamp-server", "serve"]

# Local deployment build (includes a shell and curl)
FROM golang:1.27.1-trixie@sha256:433790e515d27dc6003e847e644cc0af956985cf315c1c58a3b73ee2dd305183 AS local-deploy
# Retrieve the binary from the previous stage
COPY --from=builder /opt/app-root/src/timestamp-server /usr/local/bin/timestamp-server
# Set the binary as the entrypoint of the container
CMD ["timestamp-server", "serve"]

# Cross-compile dlv for the debug stage
FROM builder AS dlvbuilder
ARG TARGETOS
ARG TARGETARCH
ENV APP_ROOT=/opt/app-root
ENV GOPATH=$APP_ROOT
# Create a directory where 'go install' may install the cross-compiled binary,
# if the build and target platform differ.
RUN mkdir -p /opt/app-root/bin/${TARGETOS}_${TARGETARCH}
# Install dlv
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go install github.com/go-delve/delve/cmd/dlv@latest

# Build debug binary
FROM builder AS debug-builder
ARG TARGETOS
ARG TARGETARCH
ARG SERVER_LDFLAGS
# Build server for debugger with compiler optimizations disabled
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} CGO_ENABLED=0 go build -gcflags "all=-N -l" -ldflags "${SERVER_LDFLAGS}" -o timestamp-server_debug ./cmd/timestamp-server

# Multi-stage debugger build
FROM golang:1.27.1-trixie@sha256:433790e515d27dc6003e847e644cc0af956985cf315c1c58a3b73ee2dd305183 AS debug
ARG TARGETOS
ARG TARGETARCH
# Copy dlv binary, either from bin/ when the build and target platform are the same, or
# from bin/TARGETOS_TARGETARCH when the platforms are different.
COPY --from=dlvbuilder /opt/app-root/bin/dlv* /opt/app-root/bin/${TARGETOS}_${TARGETARCH}/dlv* /usr/local/bin/
# Overwrite server binary
COPY --from=debug-builder /opt/app-root/src/timestamp-server_debug /usr/local/bin/timestamp-server
# Set the binary as the entrypoint of the container
CMD ["timestamp-server", "serve"]
