# TSA Certificate Maker

This tool creates root, intermediate (optional), and leaf certificates for Timestamp Authority ([certificate requirements](tsa-policy.md)):

- Two-level chain (root -> leaf)
- Three-level chain (root -> intermediate -> leaf)

## Requirements

- Access to one of the supported KMS providers (AWS, Google Cloud, Azure)
- Pre-existing KMS keys (the tool uses existing keys and does not create new ones)

## Local Development

Build the binary:

```bash
make cert-maker
./bin/tsa-certificate-maker --help
```

## Usage

The tool can be configured using either command-line flags or environment variables.

### Command-Line Interface

Available flags:

- `--kms-type`: KMS provider type (awskms, gcpkms, azurekms, hashivault)
- `--root-key-id`: KMS key identifier for root certificate
- `--leaf-key-id`: KMS key identifier for leaf certificate
- `--aws-region`: AWS region (required for AWS KMS)
- `--azure-tenant-id`: Azure KMS tenant ID
- `--gcp-credentials-file`: Path to credentials file (for Google Cloud KMS)
- `--vault-address`: HashiCorp Vault address
- `--vault-token`: HashiCorp Vault token
- `--root-template`: Path to root certificate template
- `--leaf-template`: Path to leaf certificate template
- `--root-cert`: Output path for root certificate (default: root.pem)
- `--leaf-cert`: Output path for leaf certificate (default: leaf.pem)
- `--intermediate-key-id`: KMS key identifier for intermediate certificate
- `--intermediate-template`: Path to intermediate certificate template
- `--intermediate-cert`: Output path for intermediate certificate

### Environment Variables

- `KMS_TYPE`: KMS provider type ("awskms", "gcpkms", "azurekms", "hashivault")
- `ROOT_KEY_ID`: Key identifier for root certificate
- `KMS_INTERMEDIATE_KEY_ID`: Key identifier for intermediate certificate
- `LEAF_KEY_ID`: Key identifier for leaf certificate
- `AWS_REGION`: AWS Region (required for AWS KMS)
- `KMS_VAULT_NAME`: Azure Key Vault name
- `AZURE_TENANT_ID`: Azure tenant ID
- `GCP_CREDENTIALS_FILE`: Path to credentials file (for Google Cloud KMS)
- `VAULT_ADDR`: HashiCorp Vault address
- `VAULT_TOKEN`: HashiCorp Vault token

### Certificate Templates

The tool uses JSON templates to define certificate properties:

- `root-template.json`: Defines root CA certificate properties
- `intermediate-template.json`: Defines intermediate CA certificate properties (when using --intermediate-key-id)
- `leaf-template.json`: Defines leaf certificate properties

Templates are located in `pkg/certmaker/templates/`.

Note: Templates use ASN.1/OID format for timestamping-specific extensions.

### Provider-Specific Configuration Examples

#### AWS KMS

```shell
export KMS_TYPE=awskms
export AWS_REGION=us-east-1
export ROOT_KEY_ID=alias/root-key
export KMS_INTERMEDIATE_KEY_ID=alias/intermediate-key
export LEAF_KEY_ID=alias/leaf-key
```

#### Google Cloud KMS

```shell
export KMS_TYPE=gcpkms
export ROOT_KEY_ID=projects/PROJECT_ID/locations/LOCATION/keyRings/KEYRING/cryptoKeys/KEY_NAME/cryptoKeyVersions/VERSION
export LEAF_KEY_ID=projects/PROJECT_ID/locations/LOCATION/keyRings/KEYRING/cryptoKeys/KEY_NAME/cryptoKeyVersions/VERSION
export KMS_INTERMEDIATE_KEY_ID=projects/PROJECT_ID/locations/LOCATION/keyRings/KEYRING/cryptoKeys/KEY_NAME/cryptoKeyVersions/VERSION
```

#### Azure KMS

```shell
export KMS_TYPE=azurekms
export ROOT_KEY_ID=azurekms:name=root-key;vault=tsa-keys
export KMS_INTERMEDIATE_KEY_ID=azurekms:name=leaf-key;vault=fulcio-keys
export LEAF_KEY_ID=azurekms:name=leaf-key;vault=tsa-keys
export AZURE_TENANT_ID=83j229-83j229-83j229-83j229-83j229
```

#### HashiCorp Vault KMS

```shell
export KMS_TYPE=hashivault
export ROOT_KEY_ID=transit/keys/root-key
export KMS_INTERMEDIATE_KEY_ID=transit/keys/intermediate-key
export LEAF_KEY_ID=transit/keys/leaf-key
export VAULT_ADDR=http://vault:8200
export VAULT_TOKEN=token
```

### Example Certificate Outputs

#### TSA Leaf Certificate

```bash
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1733012132 (0x674baaa4)
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, O=Sigstore, OU=Timestamp Authority Intermediate CA, CN=https://tsa.com
        Validity
            Not Before: Jan  1 00:00:00 2024 GMT
            Not After : Jan  1 00:00:00 2034 GMT
        Subject: C=US, O=Sigstore, OU=Timestamp Authority Leaf CA, CN=https://tsa.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:f8:ca:84:0d:9d:31:da:d0:94:1f:2a:53:ff:3f:
                    f2:39:ca:90:5b:8c:26:29:28:02:a7:e2:10:80:92:
                    1b:9f:3a:03:c7:cd:36:7a:2c:2b:1c:0c:95:bc:86:
                    73:b4:55:46:0e:50:29:34:1e:07:a6:64:41:13:ca:
                    36:5d:d4:71:dd
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier:
                0D:1B:3F:95:18:04:65:60:AD:E3:28:D0:B7:43:45:BD:FE:63:5A:DF
            X509v3 Authority Key Identifier:
                0D:1B:3F:95:18:04:65:60:AD:E3:28:D0:B7:43:45:BD:FE:63:5A:DF
            X509v3 Extended Key Usage: critical
                Time Stamping
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:44:02:20:27:6e:80:88:de:6c:0f:57:be:10:f7:1d:32:97:
        73:a5:dc:6a:92:3e:26:90:4b:4b:02:05:7c:a8:85:5f:74:f4:
        02:20:5d:50:57:15:96:90:d9:82:7d:97:50:c4:8c:b7:97:a3:
        8e:0b:a3:ab:dd:26:bd:dc:cc:19:0d:99:63:5a:ce:6e
```

#### TSA Intermediate Certificate

```bash
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1733012132 (0x674baaa4)
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, O=Sigstore, OU=Timestamp Authority Root CA, CN=https://tsa.com
        Validity
            Not Before: Jan  1 00:00:00 2024 GMT
            Not After : Jan  1 00:00:00 2034 GMT
        Subject: C=US, O=Sigstore, OU=Timestamp Authority Intermediate CA, CN=https://tsa.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:f8:ca:84:0d:9d:31:da:d0:94:1f:2a:53:ff:3f:
                    f2:39:ca:90:5b:8c:26:29:28:02:a7:e2:10:80:92:
                    1b:9f:3a:03:c7:cd:36:7a:2c:2b:1c:0c:95:bc:86:
                    73:b4:55:46:0e:50:29:34:1e:07:a6:64:41:13:ca:
                    36:5d:d4:71:dd
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier:
                0D:1B:3F:95:18:04:65:60:AD:E3:28:D0:B7:43:45:BD:FE:63:5A:DF
            X509v3 Authority Key Identifier:
                BB:84:41:46:F0:A6:90:38:C0:73:1E:11:F4:58:7C:44:9B:C6:45:89
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:04:13:5f:f9:16:d8:b3:d8:cf:22:a4:f7:70:1a:
        f4:25:c5:63:97:14:2f:ac:d6:af:15:3d:e6:ad:a7:0a:08:c8:
        02:21:00:d7:63:02:ed:ef:74:9e:05:a8:86:03:ff:12:01:fb:
        21:10:74:6b:db:e7:64:65:29:3b:ae:4d:de:57:98:5c:2b
```

#### TSA Root Certificate

```bash
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1733012131 (0x674baaa3)
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, O=Sigstore, OU=Timestamp Authority Root CA, CN=https://tsa.com
        Validity
            Not Before: Jan  1 00:00:00 2024 GMT
            Not After : Jan  1 00:00:00 2034 GMT
        Subject: C=US, O=Sigstore, OU=Timestamp Authority Root CA, CN=https://tsa.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:73:77:29:2b:48:de:da:82:53:60:36:ac:9e:b7:
                    e1:78:3e:e1:d6:58:f1:7e:fa:b2:2a:28:c5:c8:d4:
                    25:c6:e8:5c:d1:63:a8:22:3e:a6:7b:bb:3b:d7:f3:
                    98:c8:25:52:12:2a:c1:fb:9b:56:af:97:77:a4:48:
                    89:be:49:bc:63
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:1
            X509v3 Subject Key Identifier:
                BB:84:41:46:F0:A6:90:38:C0:73:1E:11:F4:58:7C:44:9B:C6:45:89
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:44:02:20:5a:d8:12:e0:ad:f9:2e:18:8c:5c:40:11:62:67:
        64:3d:20:22:6b:29:48:e5:ef:c6:99:90:46:1a:6c:1c:41:bc:
        02:20:3b:cd:84:49:cf:3a:d2:9c:0d:32:59:93:b0:e5:3a:41:
        ae:02:53:88:d0:e1:9a:38:9d:1b:a5:d2:71:db:cf:a4
```

## Running the Tool

Example with AWS KMS:

```bash
tsa-certificate-maker  create \
  --kms-type awskms \
  --aws-region us-east-1 \
  --root-key-id alias/tsa-root \
  --leaf-key-id alias/tsa-leaf \
  --root-template pkg/certmaker/templates/root-template.json \
  --leaf-template pkg/certmaker/templates/leaf-template.json
```

Example with Azure KMS:

```bash
tsa-certificate-maker create \
  --kms-type azurekms \
  --azure-tenant-id 1b4a4fed-fed8-4823-a8a0-3d5cea83d122 \
  --root-key-id "azurekms:name=sigstore-key;vault=sigstore-key" \
  --leaf-key-id "azurekms:name=sigstore-key-intermediate;vault=sigstore-key" \
  --intermediate-key-id "azurekms:name=sigstore-key-intermediate;vault=sigstore-key” \
  --root-cert root.pem \
  --leaf-cert leaf.pem \
  --intermediate-cert intermediate.pem
```

Example with GCP KMS:

```bash
tsa-certificate-maker create \
  --kms-type gcpkms \
  ---gcp-credentials-file ~/.config/gcloud/application_default_credentials.json \
  --root-key-id  projects/<project_id>/locations/<location>/keyRings/<keyring>/cryptoKeys/fulcio-key1/cryptoKeyVersions/<version> \
  --intermediate-key-id projects/<project_id>/locations/<location>/keyRings/<keyring>/cryptoKeys/fulcio-key1/cryptoKeyVersions/<version> \
  --leaf-key-id projects/<project_id>/locations/<location>/keyRings/<keyring>/cryptoKeys/fulcio-key1/cryptoKeyVersions/<version> \
  --root-cert root.pem \
  --leaf-cert leaf.pem \
  --intermediate-cert intermediate.pem
```

Example with HashiCorp Vault KMS:

```bash
tsa-certificate-maker create \
  --kms-type hashivault \
  --vault-address http://vault:8200 \
  --vault-token token \
  --root-key-id "transit/keys/root-key" \
  --leaf-key-id "transit/keys/leaf-key" \
  --intermediate-key-id "transit/keys/intermediate-key” \
  --root-cert root.pem \
  --leaf-cert leaf.pem \
  --intermediate-cert intermediate.pem
```
