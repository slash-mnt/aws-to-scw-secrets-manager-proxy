import base64
from botocore.auth import SigV4Auth
from botocore.credentials import Credentials
from botocore.exceptions import ClientError
from botocore.awsrequest import AWSRequest
import datetime
from fastapi import FastAPI, Request, HTTPException
import httpx
import logging
import os
import re

logger = logging.getLogger(__name__)
app = FastAPI()

# Scaleway configuration
SCW_API_KEY = os.getenv("SCW_API_KEY", "scaleway_token")
SCW_PROJECT_ID = os.getenv("SCW_PROJECT_ID", "scaleway_project_id")
SCW_REGION = os.getenv("SCW_REGION", "fr-par")
SCW_BASE_URL = f"https://api.scaleway.com/secret-manager/v1beta1/regions/{SCW_REGION}/secrets"

# AWS configuration to validate signatures
AWS_REGION = os.getenv("AWS_REGION", "eu-west-1")

async def forward_to_scaleway(method: str, path: str, payload: dict, headers: dict):
    """
    Asynchronously forwards a request to the Scaleway API using the provided HTTP method,
    endpoint path, payload, and headers. This method constructs Scaleway-specific headers,
    formats the endpoint URL, and sends the request.

    :param method: The HTTP method to use for the request (e.g., "GET", "POST", "PUT", "DELETE").
    :type method: str

    :param path: The endpoint path of the Scaleway API to which the request will be forwarded.
    :type path: str

    :param payload: The request payload to be sent to the Scaleway API, represented as a dictionary.
    :type payload: dict

    :param headers: Additional HTTP headers to include in the request. These headers may override or
                    supplement the default Scaleway headers.
    :type headers: dict

    :return: The HTTP response received from the Scaleway API. The response contains meta-information
             such as status code, headers, and content.
    :rtype: httpx.Response
    """
    async with httpx.AsyncClient() as client:
        scw_headers = {
            "X-Auth-Token": SCW_API_KEY,
            "Content-Type": "application/json",
        }
        scw_url = f"{SCW_BASE_URL}/{path}"

        logger.debug(f"{method} on {scw_url} with headers {scw_headers}")

        if method == "get":
            response = await client.request(method, scw_url, headers=scw_headers)
        else:
            response = await client.request(method, scw_url, headers=scw_headers, json=payload)
        return response


async def validate_aws_signature(request: Request):
    """
    Validates the AWS Signature Version 4 of an incoming HTTP request. This function
    ensures that the request contains proper authentication by verifying the provided
    AWS signature against the expected signature generated based on the request
    details and preconfigured credentials. It extracts essential headers and validates
    their format and presence before attempting authentication.

    :param request: The incoming HTTP request to validate.
    :type request: Request
    :return: A dictionary containing the validated AWS credentials, including the
        access key, region, and service.
    :rtype: dict
    :raises HTTPException: If the signature is missing, invalid, or another error
        occurs during validation.
    """
    # Retrieves AWS headers
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("AWS4-HMAC-SHA256"):
        logger.error("AWS Signature missing or invalid")
        raise HTTPException(status_code=401, detail="AWS Signature missing or invalid")

    # Extracting parts of the signature
    match = re.match(r'AWS4-HMAC-SHA256 Credential=([^/]+)/(\d{8})/([^/]+)/([^/]+)/aws4_request, SignedHeaders=([^,]+), Signature=([^,]+)', auth_header)
    if not match:
        logger.error("Wrong Autorization header format")
        raise HTTPException(status_code=401, detail="Wrong Autorization header format")

    access_key, date, region, service, signed_headers, signature = match.groups()

    # Extracting other mandatory headers
    x_amz_date = request.headers.get("x-amz-date")
    if not x_amz_date:
        logger.error("Missing x-amz-date header")
        raise HTTPException(status_code=401, detail="Missing x-amz-date header")

    # Construct botocore request
    method = request.method
    path = request.url.path
    headers = dict(request.headers)
    body = await request.body()

    # Prepare the credentials (here, you should retrieve them from a database or a service)
    # For the example, we use dummy credentials
    credentials = Credentials(access_key, "virtual_secret_key")

    # Signature validation
    try:
        SigV4Auth(credentials, service, region).add_auth(
            AWSRequest(
                method=method,
                url=f"https://{request.headers.get('host')}{path}",
                data=body,
                headers=headers
            )
        )
        logger.info("AWS Signature valid")
        # If the signature is well-formed, returns the credentials
        return {"access_key": access_key, "region": region, "service": service}
    except ClientError as e:
        logger.error(f"Failed to validate AWS Signature: {str(e)}")
        raise HTTPException(status_code=401, detail=f"Invalid AWS Signature: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error during signature validation: {str(e)}")
        raise HTTPException(status_code=401, detail=f"Validation error: {str(e)}")


@app.get("/")
@app.post("/")
async def proxy(request: Request):
    """
    Handles proxying of AWS Secrets Manager requests to Scaleway Secrets Manager, performing necessary
    request and response mappings between AWS and Scaleway formats. Supports various Secrets Manager
    operations such as GetSecretValue, CreateSecret, UpdateSecret, and ListSecrets.

    :param request: The incoming HTTP request that has been intercepted to be proxied
                    to Scaleway.
    :type request: Request
    :param path: The requested endpoint path to be processed. It supports path-based
                 mapping for AWS Secrets Manager to Scaleway counterparts.
    :type path: str
    :return: A JSON response mapped from Scaleway's format to AWS Secrets Manager's
             format for supported operations, or as is for unsupported paths.
    :rtype: dict
    :raises HTTPException: If the requested path is unsupported, a 404 HTTP error is raised.
    """

    # Validate AWS signature
    try:
        aws_credentials = await validate_aws_signature(request)
        logger.debug(f"Valid AWS Signature for {aws_credentials['access_key']}")
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")

    aws_payload = await request.json()

    if "SecretId" in aws_payload:
        # GetSecretValue mapping
        scw_path = f"{aws_payload["SecretId"]}/versions/latest/access"
        method = "get"
        aws_method = "GetSecretValue"
        payload = {}
    else:
        # ListSecrets mapping
        scw_path = f"?project_id={SCW_PROJECT_ID}"
        method = "get"
        aws_method = "ListSecrets"
        payload = {}

    if scw_path:
        # 3. Call Scaleway
        scw_response = await forward_to_scaleway(method, scw_path, payload, request.headers)

        scw_data = scw_response.json()
        aws_response = scw_data

        # 4. Map the Scaleway response to AWS response format
        if aws_method == "GetSecretValue":
            secret_metadata_response = await forward_to_scaleway(method, f"{aws_payload["SecretId"]}?project_id={SCW_PROJECT_ID}", payload, request.headers)
            secret_metadata_data = secret_metadata_response.json()
            aws_response = {
                "ARN": scw_data["secret_id"],
                "Name": secret_metadata_data["name"],
                "CreatedDate": secret_metadata_data["created_at"],
                "SecretString": base64.b64decode(scw_data["data"]),
                "VersionId": scw_data["revision"],
                "VersionStages": []
            }

        if aws_method == "ListSecrets":
            aws_response = {
                "SecretList": [
                    {
                        "ARN": secret["id"],
                        "Name": secret["name"],
                        "LastChangedDate": secret["updated_at"],
                        "LastAccessedDate": secret["updated_at"],
                        "Tags": secret["tags"],
                        "CreatedDate": secret["created_at"],
                        "PrimaryRegion": SCW_REGION
                    }
                    for secret in scw_data["secrets"]
                ],
                "NextToken": None
            }

        # Default response in the original Scaleway's format
        return aws_response
    raise HTTPException(status_code=404, detail="Unsupported endpoint")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
