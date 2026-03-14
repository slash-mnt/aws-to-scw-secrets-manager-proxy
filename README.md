# AWS-to-Scaleway Secrets Manager Proxy

A lightweight HTTP proxy server that translates AWS Secrets Manager API calls to Scaleway Secrets Manager API calls.
This allows tools like [MinIO KES](https://github.com/minio/kes) to use Scaleway Secrets Manager without code changes.

---

## Concept

This proxy intercepts AWS Secrets Manager API requests, validates their AWS Signature V4, and forwards them to Scaleway
Secrets Manager after translating endpoints, parameters, and responses. It is designed to be transparent to clients, so
they continue to use AWS SDKs or tools while actually interacting with Scaleway.

### Key Features

* **Transparent Proxy**: No changes required in client applications (e.g., KES).
* **AWS Signature V4 Validation**: Ensures only authorized requests are processed.
* **Endpoint Mapping**: Translates AWS endpoints to Scaleway equivalents.
* **Response Format Mapping**: Converts Scaleway responses to AWS-compatible formats.

List of covered features:

* ListSecrets
* GetSecretValue
* CreateSecret

---

## Prerequisites

* Python 3.8+
* FastAPI
* `httpx` for HTTP requests
* `botocore` for AWS signature validation
* `uvicorn` for HTTP server
* `uuid` for UUID generation
* Scaleway API key with Secrets Manager access

Install dependencies:
```bash
pip install -r requirements.txt
```

## Configuration

Set your Scaleway project ID as environment variables:

```
export SCW_PROJECT_ID="xx-xx-xx"
```

Others environment variables are optional:

* `DEFAULT_SECRET_PATH`: holds the secret path within the Scaleway Secrets Manager (default to: `/minio/kes/kes`)
* `AWS_REGION`: the region displayed in the ARN (defaults to `eu-west-3`)

## Run the proxy

```shell
python main.py

# or
uvicorn main\:app --host 0.0.0.0 --port 8000
```

## Test examples

### List Secrets

```shell
aws secretsmanager list-secrets --endpoint-url http://localhost:8000
```

### Get a Secret value

```shell
aws secretsmanager get-secret-value --secret-id xxxx-xxxx-xxxx-xxxx --endpoint-url http://localhost:8000
```

## KES Usage specific

The KES (MinIO) keeps the key in its cache for a while. It avoids requesting multiple times keys in a short window of time.

### Configuring KES

The only thing to change is the `keystore.aws.secretsmanager.endpoint`, `keystore.aws.secretsmanager.region` and
`keystore.aws.secretsmanager.credentials`:

```
keystore:
     aws:
       secretsmanager:
         endpoint: http://localhost:8000 # This is the AWS-to-SCW proxy endpoint
         region:   fr-par
         kmskey:   ""
         credentials:
           accesskey: "<SCW_TOKEN_API>"
           secretkey: "<whatever you want, it will be discarded>"
```