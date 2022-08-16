//
// Copyright 2022 The Sigstore Authors.
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

package app

import (
	"fmt"
	"log"
	"strings"
	"time"

	validator "github.com/go-playground/validator/v10"
	"github.com/pkg/errors"
	"github.com/spf13/pflag"
)

type FlagType string

const (
	fileFlag    FlagType = "file"
	urlFlag     FlagType = "url"
	oidFlag     FlagType = "oid"
	formatFlag  FlagType = "format"
	timeoutFlag FlagType = "timeout"
)

type newPFlagValueFunc func() pflag.Value

var pflagValueFuncMap map[FlagType]newPFlagValueFunc

// TODO: unit tests for all of this
func initializePFlagMap() {
	pflagValueFuncMap = map[FlagType]newPFlagValueFunc{
		fileFlag: func() pflag.Value {
			// this validates that the file exists and can be opened by the current uid
			return valueFactory(fileFlag, validateString("required,file"), "")
		},
		urlFlag: func() pflag.Value {
			// this validates that the string is a valid http/https URL
			return valueFactory(urlFlag, validateString("required,url,startswith=http|startswith=https"), "")
		},
		oidFlag: func() pflag.Value {
			// this validates for an OID, which is a sequence of positive integers separated by periods
			return valueFactory(oidFlag, validateOID, "")
		},
		formatFlag: func() pflag.Value {
			// this validates the output format requested
			return valueFactory(formatFlag, validateString("required,oneof=json default"), "")
		},
		timeoutFlag: func() pflag.Value {
			// this validates the timeout is >= 0
			return valueFactory(formatFlag, validateTimeout, "")
		},
	}
}

// NewFlagValue creates a new pflag.Value for the specified type with the specified default value.
// If a default value is not desired, pass "" for defaultVal.
func NewFlagValue(flagType FlagType, defaultVal string) pflag.Value {
	valFunc := pflagValueFuncMap[flagType]
	val := valFunc()
	if defaultVal != "" {
		if err := val.Set(defaultVal); err != nil {
			log.Fatal(errors.Wrap(err, "initializing flag"))
		}
	}
	return val
}

type validationFunc func(string) error

func valueFactory(flagType FlagType, v validationFunc, defaultVal string) pflag.Value {
	return &baseValue{
		flagType:       flagType,
		validationFunc: v,
		value:          defaultVal,
	}
}

// baseValue implements pflag.Value
type baseValue struct {
	flagType       FlagType
	value          string
	validationFunc validationFunc
}

// Type returns the type of this Value
func (b baseValue) Type() string {
	return string(b.flagType)
}

// String returns the string representation of this Value
func (b baseValue) String() string {
	return b.value
}

// Set validates the provided string against the appropriate validation rule
// for b.flagType; if the string validates, it is stored in the Value and nil is returned.
// Otherwise the validation error is returned but the state of the Value is not changed.
func (b *baseValue) Set(s string) error {
	if err := b.validationFunc(s); err != nil {
		return err
	}
	b.value = s
	return nil
}

// validateOID ensures that the supplied string is a valid ASN.1 object identifier
func validateOID(v string) error {
	o := struct {
		Oid []string `validate:"dive,numeric"`
	}{strings.Split(v, ".")}

	return useValidator(oidFlag, o)
}

// validateTimeout ensures that the supplied string is a valid time.Duration value >= 0
func validateTimeout(v string) error {
	duration, err := time.ParseDuration(v)
	if err != nil {
		return err
	}
	d := struct {
		Duration time.Duration `validate:"min=0"`
	}{duration}
	return useValidator(timeoutFlag, d)
}

// validateString returns a function that validates an input string against the specified tag,
// as defined in the format supported by go-playground/validator
func validateString(tag string) validationFunc {
	return func(v string) error {
		validator := validator.New()
		return validator.Var(v, tag)
	}
}

// useValidator performs struct level validation on s as defined in the struct's tags using
// the go-playground/validator library
func useValidator(flagType FlagType, s interface{}) error {
	validate := validator.New()
	if err := validate.Struct(s); err != nil {
		return fmt.Errorf("error parsing %v flag: %w", flagType, err)
	}

	return nil
}
