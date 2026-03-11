# AWS-to-Scaleway Secrets Manager Proxy

A lightweight HTTP proxy server that translates AWS Secrets Manager API calls to Scaleway Secrets Manager API calls.
This allows tools like [MinIO KES](https://github.com/minio/kes) to use Scaleway Secrets Manager without code changes.

---

## Concept

This proxy intercepts AWS Secrets Manager API requests, validates their AWS Signature V4, and forwards them to Scaleway
Secrets Manager after translating endpoints, parameters, and responses. It is designed to be transparent to clients, so
they continue to use AWS SDKs or tools while actually interacting with Scaleway.

### Key Features

- **Transparent Proxy**: No changes required in client applications (e.g., KES).
- **AWS Signature V4 Validation**: Ensures only authorized requests are processed.
- **Endpoint Mapping**: Translates AWS endpoints (e.g., `ListSecrets`, `GetSecretValue`) to Scaleway equivalents.

---

## Prerequisites

- Python 3.8+
- FastAPI
- `httpx` for HTTP requests
- `botocore` for AWS signature validation
- Scaleway API key with Secrets Manager access

Install dependencies:
```bash
pip install fastapi uvicorn httpx botocore structlog
```

## Configuration

Set your Scaleway API key and AWS region as environment variables:

```
export SCW_API_KEY="your_scaleway_api_key"
export SCW_REGION="fr-par"
export SCW_PROJECT_ID="xx-xx-xx"
export AWS_REGION="eu-west-3"
```

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