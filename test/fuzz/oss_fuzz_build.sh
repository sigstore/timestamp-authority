#!/usr/bin/env bash

# Copyright 2025 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
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

go get github.com/AdamKorcz/go-118-fuzz-build/testing

compile_native_go_fuzzer github.com/sigstore/timestamp-authority/v2/pkg/api FuzzParseJSONRequest FuzzParseJSONRequest
compile_native_go_fuzzer github.com/sigstore/timestamp-authority/v2/pkg/api FuzzParseDERRequest FuzzParseDERRequest

zip -qj $OUT/FuzzParseJSONRequest_seed_corpus.zip $SRC/go-fuzz-corpus/json/corpus/*
cp $SRC/afl-fuzz/dictionaries/json.dict $OUT/FuzzParseJSONRequest.dict
