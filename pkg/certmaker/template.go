// Package certmaker provides template parsing and certificate generation functionality
// for creating X.509 certificates from JSON templates per RFC3161 standards. It supports both root and
// intermediate certificate creation with configurable properties including key usage,
// extended key usage, and basic constraints.
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

// CertificateTemplate defines the JSON structure for X.509 certificate templates
// including subject, issuer, validity period, and certificate constraints.
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
	NotBefore        string   `json:"notBefore"`
	NotAfter         string   `json:"notAfter"`
	KeyUsage         []string `json:"keyUsage"`
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
// CA certs: verifies proper key usage is set.
// non-CA certs: verifies digitalSignature usage is set.
func ValidateTemplate(tmpl *CertificateTemplate, parent *x509.Certificate) error {
	if tmpl.Subject.CommonName == "" {
		return fmt.Errorf("template subject.commonName cannot be empty")
	}

	if parent == nil && tmpl.Issuer.CommonName == "" {
		return fmt.Errorf("template issuer.commonName cannot be empty for root certificate")
	}

	// For CA certs
	if tmpl.BasicConstraints.IsCA {
		if len(tmpl.KeyUsage) == 0 {
			return fmt.Errorf("CA certificate must specify at least one key usage")
		}
		hasKeyUsageCertSign := false
		for _, usage := range tmpl.KeyUsage {
			if usage == "certSign" {
				hasKeyUsageCertSign = true
				break
			}
		}
		if !hasKeyUsageCertSign {
			return fmt.Errorf("CA certificate must have certSign key usage")
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

// CreateCertificateFromTemplate generates an x509.Certificate from the provided template
// applying all specified attributes including subject, issuer, validity period,
// constraints and extensions.
func CreateCertificateFromTemplate(tmpl *CertificateTemplate, parent *x509.Certificate) (*x509.Certificate, error) {
	notBefore, err := time.Parse(time.RFC3339, tmpl.NotBefore)
	if err != nil {
		return nil, fmt.Errorf("invalid notBefore time format: %w", err)
	}

	notAfter, err := time.Parse(time.RFC3339, tmpl.NotAfter)
	if err != nil {
		return nil, fmt.Errorf("invalid notAfter time format: %w", err)
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
	}

	SetKeyUsages(cert, tmpl.KeyUsage)

	// Sets extensions
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

// SetKeyUsages applies the specified key usage to cert(s)
// supporting certSign, crlSign, and digitalSignature usages.
func SetKeyUsages(cert *x509.Certificate, usages []string) {
	for _, usage := range usages {
		switch usage {
		case "certSign":
			cert.KeyUsage |= x509.KeyUsageCertSign
		case "crlSign":
			cert.KeyUsage |= x509.KeyUsageCRLSign
		case "digitalSignature":
			cert.KeyUsage |= x509.KeyUsageDigitalSignature
		}
	}
}
