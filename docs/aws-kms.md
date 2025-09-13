# Using AWS KMS to generate certificates and run `timestamp-authority`

It's possible to generate certificates for a `timestamp-authority` server using keys that are in AWS Key Management Service; the process follows [the general instructions for using other KMSs](https://github.com/sigstore/timestamp-authority/tree/main?tab=readme-ov-file#other-kmss), and uses [Certificate Maker](https://github.com/sigstore/fulcio/blob/main/docs/certificate-maker.md) to generate the certificates.

## Create the AWS KMS keys

First, you will need to create the Amazon KMS keys; you can either create two keys (one for your root certificate and one for your leaf certificate), or create three (root, intermediate, and leaf). The keys should all be created with key type of **asymmetric**, key usage of **sign and verify**, and then a key spec that you know will be supported by whatever clients are going to be using your timestamp service (**RSA_4096** is probably a safe bet). Set the permissions so that the keys will be usable by whatever AWS identity you'll use when running the timestamp server (e.g., you can create a new IAM user and then include it as one of the key users, or any other of the million ways you can assign permissions for an AWS identity to use the keys).

Once you've created the keys, you'll want to note the ARNs for each; you'll need them when running Certificate Maker, and then you'll need the leaf key ARN when running your timestamp authority server.

## Use Certificate Maker to create your certificates

Next, you will need to clone the [`fulcio`](https://github.com/sigstore/fulcio/) repository, which contains the Certificate Maker utility, and build the utility itself:

```shell
git clone https://github.com/sigstore/fulcio/
cd fulcio
make cert-maker
```

Create a work directory somewhere, and create templates for your certificates (either a root and leaf template, or root, intermediate, and leaf templates). [Example templates are included in this project](https://github.com/sigstore/timestamp-authority/tree/main/pkg/certmaker/templates), but you will want to copy them into your work directory and modify them appropriate to your needs:

* set `commonName` to a meaningful value in each template (e.g., "Acme Corp Timestamp Root CA", "Acme Corp Timestamp Intermediate CA", and "Acme Corp Timestamp Leaf");
* set the `country`, `organization`, and `organizationalUnit` values;
* make any other changes you might need (e.g., setting `locality` or `province`, adding other permissible key usages, etc.).

Set your `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` environment variables with values corresponding to the AWS identity which has permission to use your newly-created KMS keys, and then run `certificate-maker` to create your new certificates, replacing the `{YOUR-VALUE}` values:

### Root and leaf certificates

```shell
/path/to/certificate-maker create \
    --kms-type=awskms \
    --aws-region={YOUR-REGION} \
    --root-key-id={YOUR-ROOT-KEY-ARN} \
    --leaf-key-id={YOUR-LEAF-KEY-ARN} \
    --root-template=./root-template.json \
    --leaf-template=./leaf-template.json
```

### Root, intermediate, and leaf certificates

```shell
/path/to/certificate-maker create \
    --kms-type=awskms \
    --aws-region={YOUR-REGION} \
    --root-key-id={YOUR-ROOT-KEY-ARN} \
    --intermediate-key-id={YOUR-INTERMEDIATE-KEY-ARN} \
    --leaf-key-id={YOUR-LEAF-KEY-ARN} \
    --root-template=./root-template.json \
    --intermediate-template=./intermediate-template.json \
    --leaf-template=./leaf-template.json
```

This should result in files for each of your new certificates (e.g., `root.pem`, `leaf.pem`, and then `intermediate.pem` if you generated an intermediate certificate).

Concatenate all your certificates into a single file, with the leaf certificate first, the intermediate cert next (if you generated one), and then the root certificate:

```shell
cat leaf.pem intermediate.pem root.pem > certchain.pem
```

## Run your timestamp authority server

Finally, run `timestamp-server`, specifying that your timestamp authority signer is a KMS, pointing it to your full certificate chain, and providing the ARN for the AWS KMS key you created for your leaf certificate (noting that AWS KMS keys are specified with the prefix `awskms:///`, with **three** slashes before the ARN):

```shell
timestamp-server serve \
    --host=0.0.0.0 \
    --port=3004 \
    --timestamp-signer=kms \
    --certificate-chain-path=/path/to/certchain.pem \
    --kms-key-resource=awskms:///{YOUR-LEAF-KEY-ARN} \
    --log-type=prod
```

(Note that the shell running `timestamp-server` needs to have access to the AWS access key and secret for the identity with permission to use the leaf key, so you'll need to either export environment variables for `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`, or have Docker set the environemnt variables appropriately, or however else you're choosing to run the server.)
