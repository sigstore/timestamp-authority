# Certificate Maker

_Note: Certificate Maker can be [found in the Fulcio repository](https://github.com/sigstore/fulcio/tree/main/cmd/certificate_maker). Please refer to its [respective documentation](https://github.com/sigstore/fulcio/blob/main/docs/certificate-maker.md) to learn more._

The TSA-specific certificate templates located in the `/pkg/certmaker/templates` can be used with Certificate Maker.

## Templates

These [TSA-specific certificate templates](/pkg/certmaker/templates) are specifically configured for Timestamp Authority certificates with appropriate extensions and constraints:

- `root-template.json`: Template for root CA certificates
- `intermediate-template.json`: Template for intermediate CA certificates
- `leaf-template.json`: Template for leaf (TSA) certificates
