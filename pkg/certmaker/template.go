// Copyright 2024 The Sigstore Authors.
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
//

// Package certmaker provides template parsing and certificate generation functionality
// for creating X.509 certificates from JSON templates per RFC3161 standards.
package certmaker

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"text/template"
	"time"

	"go.step.sm/crypto/x509util"
)

// CertificateTemplate defines the structure for the JSON certificate templates
type CertificateTemplate struct {
	Subject struct {
		Country            []string `json:"country,omitempty"`
		Organization       []string `json:"organization,omitempty"`
		OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
		CommonName         string   `json:"commonName"`
	} `json:"subject"`
	Issuer struct {
		CommonName string `json:"commonName"`
	} `json:"issuer"`
	CertLifetime     string   `json:"certLife"` // Duration string e.g. "8760h" for 1 year
	KeyUsage         []string `json:"keyUsage"`
	ExtKeyUsage      []string `json:"extKeyUsage,omitempty"`
	BasicConstraints struct {
		IsCA       bool `json:"isCA"`
		MaxPathLen int  `json:"maxPathLen"`
	} `json:"basicConstraints"`
	Extensions []struct {
		ID       string `json:"id"`
		Critical bool   `json:"critical"`
		Value    string `json:"value"`
	} `json:"extensions,omitempty"`
}

// TemplateData holds context data passed to the template parser
type TemplateData struct {
	Parent *x509.Certificate
}

// ParseTemplate creates an x509 certificate from JSON template
func ParseTemplate(filename string, parent *x509.Certificate) (*x509.Certificate, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading template file: %w", err)
	}

	data := &TemplateData{
		Parent: parent,
	}

	// Borrows x509util functions to create template
	tmpl, err := template.New("cert").Funcs(x509util.GetFuncMap()).Parse(string(content))
	if err != nil {
		return nil, fmt.Errorf("leaf template error: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("leaf template error: %w", err)
	}

	// Parse template as JSON
	var certTmpl CertificateTemplate
	if err := json.Unmarshal(buf.Bytes(), &certTmpl); err != nil {
		return nil, fmt.Errorf("leaf template error: invalid JSON after template execution: %w", err)
	}

	if err := ValidateTemplate(&certTmpl, parent); err != nil {
		return nil, fmt.Errorf("template validation error: %w", err)
	}

	return CreateCertificateFromTemplate(&certTmpl, parent)
}

// ValidateTemplate performs validation checks on the certificate template.
func ValidateTemplate(tmpl *CertificateTemplate, parent *x509.Certificate) error {
	var notBefore, notAfter time.Time
	var err error

	if tmpl.CertLifetime != "" {
		duration, err := time.ParseDuration(tmpl.CertLifetime)
		if err != nil {
			return fmt.Errorf("invalid certLife format: %w", err)
		}
		if duration <= 0 {
			return fmt.Errorf("certLife must be positive")
		}
		notBefore = time.Now().UTC()
		notAfter = notBefore.Add(duration)
	} else {
		if tmpl.CertLifetime == "" {
			return fmt.Errorf("certLife must be specified")
		}
		notBefore, err = time.Parse(time.RFC3339, tmpl.CertLifetime)
		if err != nil {
			return fmt.Errorf("invalid certLife format: %w", err)
		}
		notAfter, err = time.Parse(time.RFC3339, tmpl.CertLifetime)
		if err != nil {
			return fmt.Errorf("invalid certLife format: %w", err)
		}
	}

	if notBefore.After(notAfter) {
		return fmt.Errorf("NotBefore time must be before NotAfter time")
	}

	if tmpl.Subject.CommonName == "" {
		return fmt.Errorf("template subject.commonName cannot be empty")
	}
	if parent == nil && tmpl.Issuer.CommonName == "" {
		return fmt.Errorf("template issuer.commonName cannot be empty for root certificate")
	}

	// Check if the certificate has certSign key usage
	hasKeyUsageCertSign := false
	for _, usage := range tmpl.KeyUsage {
		if usage == "certSign" {
			hasKeyUsageCertSign = true
			break
		}
	}

	// For certificates with certSign key usage, they must be CA certificates
	if hasKeyUsageCertSign && !tmpl.BasicConstraints.IsCA {
		return fmt.Errorf("CA certificate must have isCA set to true")
	}

	// For CA certs
	if tmpl.BasicConstraints.IsCA {
		if len(tmpl.KeyUsage) == 0 {
			return fmt.Errorf("CA certificate must specify at least one key usage")
		}
		if !hasKeyUsageCertSign {
			return fmt.Errorf("CA certificate must have certSign key usage")
		}

		// For root certificates, the SKID and AKID should match
		if parent == nil && len(tmpl.Extensions) > 0 {
			var hasAKID, hasSKID bool
			var akidValue, skidValue string
			for _, ext := range tmpl.Extensions {
				if ext.ID == "2.5.29.35" { // AKID OID
					hasAKID = true
					akidValue = ext.Value
				} else if ext.ID == "2.5.29.14" { // SKID OID
					hasSKID = true
					skidValue = ext.Value
				}
			}
			if hasAKID && hasSKID && akidValue != skidValue {
				return fmt.Errorf("root certificate SKID and AKID must match")
			}
		}
	} else {
		// For non-CA certs
		if len(tmpl.KeyUsage) == 0 {
			return fmt.Errorf("certificate must specify at least one key usage")
		}
		hasDigitalSignature := false
		for _, usage := range tmpl.KeyUsage {
			if usage == "digitalSignature" {
				hasDigitalSignature = true
				break
			}
		}
		if !hasDigitalSignature {
			return fmt.Errorf("timestamp authority certificate must have digitalSignature key usage")
		}

		// Check for TimeStamping extended key usage
		hasTimeStamping := false

		// Check extKeyUsage field first
		if len(tmpl.ExtKeyUsage) > 0 {
			for _, usage := range tmpl.ExtKeyUsage {
				if usage == "TimeStamping" {
					hasTimeStamping = true
					break
				}
			}
		}

		// If not found in extKeyUsage, check Extensions
		if !hasTimeStamping {
			for _, ext := range tmpl.Extensions {
				if ext.ID == "2.5.29.37" { // Extended Key Usage OID
					// Decode the base64 value
					value, err := base64.StdEncoding.DecodeString(ext.Value)
					if err != nil {
						return fmt.Errorf("error decoding extension value: %w", err)
					}
					// Check if the value contains the TimeStamping OID (1.3.6.1.5.5.7.3.8)
					if bytes.Contains(value, []byte{0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08}) {
						hasTimeStamping = true
						break
					}
				}
			}
		}

		if !hasTimeStamping {
			return fmt.Errorf("timestamp authority certificate must have TimeStamping extended key usage")
		}
	}

	// Validate extensions
	for _, ext := range tmpl.Extensions {
		if ext.ID == "" {
			return fmt.Errorf("extension ID cannot be empty")
		}
		// Validate OID format
		for _, n := range strings.Split(ext.ID, ".") {
			if _, err := strconv.Atoi(n); err != nil {
				return fmt.Errorf("invalid OID component in extension: %s", ext.ID)
			}
		}
	}

	return nil
}

// CreateCertificateFromTemplate creates an x509.Certificate from the provided template
func CreateCertificateFromTemplate(tmpl *CertificateTemplate, parent *x509.Certificate) (*x509.Certificate, error) {
	var notBefore, notAfter time.Time
	var err error

	if tmpl.CertLifetime != "" {
		duration, err := time.ParseDuration(tmpl.CertLifetime)
		if err != nil {
			return nil, fmt.Errorf("invalid certLife format: %w", err)
		}
		notBefore = time.Now().UTC()
		notAfter = notBefore.Add(duration)
	} else {
		notBefore, err = time.Parse(time.RFC3339, tmpl.CertLifetime)
		if err != nil {
			return nil, fmt.Errorf("invalid certLife format: %w", err)
		}
		notAfter, err = time.Parse(time.RFC3339, tmpl.CertLifetime)
		if err != nil {
			return nil, fmt.Errorf("invalid certLife format: %w", err)
		}
	}

	if notBefore.After(notAfter) {
		return nil, fmt.Errorf("NotBefore time must be before NotAfter time")
	}

	cert := &x509.Certificate{
		Subject: pkix.Name{
			Country:            tmpl.Subject.Country,
			Organization:       tmpl.Subject.Organization,
			OrganizationalUnit: tmpl.Subject.OrganizationalUnit,
			CommonName:         tmpl.Subject.CommonName,
		},
		Issuer: func() pkix.Name {
			if parent != nil {
				return parent.Subject
			}
			return pkix.Name{CommonName: tmpl.Issuer.CommonName}
		}(),
		SerialNumber:          big.NewInt(time.Now().Unix()),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  tmpl.BasicConstraints.IsCA,
		ExtraExtensions:       []pkix.Extension{},
	}

	if tmpl.BasicConstraints.IsCA {
		cert.MaxPathLen = tmpl.BasicConstraints.MaxPathLen
		cert.MaxPathLenZero = tmpl.BasicConstraints.MaxPathLen == 0
	} else {
		// For non-CA certificates, set the extended key usage
		for _, usage := range tmpl.ExtKeyUsage {
			if usage == "TimeStamping" {
				cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsageTimeStamping)
			}
		}
	}

	SetCertificateUsages(cert, tmpl.KeyUsage, tmpl.ExtKeyUsage)

	// Sets extensions (e.g. Timestamping)
	for _, ext := range tmpl.Extensions {
		var oid []int
		for _, n := range strings.Split(ext.ID, ".") {
			i, err := strconv.Atoi(n)
			if err != nil {
				return nil, fmt.Errorf("invalid OID in extension: %s", ext.ID)
			}
			oid = append(oid, i)
		}

		extension := pkix.Extension{
			Id:       oid,
			Critical: ext.Critical,
		}

		value, err := base64.StdEncoding.DecodeString(ext.Value)
		if err != nil {
			return nil, fmt.Errorf("error decoding extension value: %w", err)
		}
		extension.Value = value

		cert.ExtraExtensions = append(cert.ExtraExtensions, extension)
	}

	return cert, nil
}

// SetCertificateUsages applies both basic key usages and extended key usages to the certificate.
// Supports basic usages: certSign, crlSign, digitalSignature
// Supports extended usages: CodeSigning, TimeStamping
func SetCertificateUsages(cert *x509.Certificate, keyUsages []string, extKeyUsages []string) {
	// Set basic key usages
	for _, usage := range keyUsages {
		switch usage {
		case "certSign":
			cert.KeyUsage |= x509.KeyUsageCertSign
		case "crlSign":
			cert.KeyUsage |= x509.KeyUsageCRLSign
		case "digitalSignature":
			cert.KeyUsage |= x509.KeyUsageDigitalSignature
		}
	}

	// Set extended key usages
	for _, usage := range extKeyUsages {
		switch usage {
		case "CodeSigning":
			cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsageCodeSigning)
		case "TimeStamping":
			cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsageTimeStamping)
		}
	}
}
