//
// Copyright 2023 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmdparams

// IsHTTPPingOnly is set off the command-line flag to enforce limiting
// the non-mTLS http server to only serving the /ping entrypoint.
// It should be set only once when processing command-line flags
// and then used only in pkg/generated/restapi/configure_timestamp_server.go
// and as read-only.
var IsHTTPPingOnly bool
