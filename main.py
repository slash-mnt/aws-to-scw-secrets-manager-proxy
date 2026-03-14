import base64
from botocore.auth import SigV4Auth
from botocore.credentials import Credentials
from botocore.exceptions import ClientError
from botocore.awsrequest import AWSRequest
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import JSONResponse
import httpx
import logging
import os
import re
import uuid
import uvicorn

debug = False
logging.basicConfig(level=logging.DEBUG if debug else logging.INFO)
logger = logging.getLogger(__name__)
logging_config = uvicorn.config.LOGGING_CONFIG

if debug:
    logging_config["loggers"]["uvicorn"]["level"] = "DEBUG"
    logging_config["loggers"]["uvicorn.error"]["level"] = "DEBUG"
    logging_config["loggers"]["uvicorn.access"]["level"] = "DEBUG"

logging_config["loggers"][__name__] = {
    "handlers": ["default"],
    "level": "DEBUG" if debug else "INFO",
    "propagate": False,
}

app = FastAPI()

# Scaleway configuration
SCW_PROJECT_ID = os.getenv("SCW_PROJECT_ID", "scaleway_project_id")
DEFAULT_SECRET_PATH = os.getenv("DEFAULT_SECRET_PATH", "/minio/kes/key")

# AWS configuration to validate signatures
AWS_REGION = os.getenv("AWS_REGION", "eu-west-3")

# Use a small cache object to store secret ids, avoiding listing secrets everytime.
# Secret names are unique within a project.
# Cache keys are the secret name, values are their ids.
cache_ids = {}

async def forward_to_scaleway(method: str, path: str, payload: dict, region: str, api_token: str):
    """
    Forwards an HTTP request to a Scaleway API endpoint and returns the response.

    This function uses the `httpx.AsyncClient` to send a request to the Scaleway API. The method of
    the request (e.g., "get", "post"), the path of the Scaleway endpoint, and any payload to be
    included in the request are all parameterized. Authentication headers are added automatically.

    The function logs both the request details and the response received from Scaleway for debugging
    purposes. If the response has a status code indicating an error (>=400), an HTTPException is
    raised with details from the error response.

    :param method: The HTTP method for the request (e.g., "get", "post").
    :type method: str
    :param path: The endpoint path for the Scaleway API request (excluding the base URL).
    :type path: str
    :param payload: A dictionary containing the request body (ignored for "get" requests).
    :type payload: dict
    :return: The HTTP response object received from the Scaleway API.
    :rtype: httpx.Response
    :raises HTTPException: If the Scaleway API returns a response with a 4xx or 5xx status code.
    """
    async with httpx.AsyncClient() as client:
        scw_headers = {
            "X-Auth-Token": api_token,
            "Content-Type": "application/json",
        }
        scw_base_url = f"https://api.scaleway.com/secret-manager/v1beta1/regions/{region}/secrets"
        scw_url = f"{scw_base_url}{path}"

        logger.debug(f"{method} on {scw_url} with headers {scw_headers}: {payload}")

        if method == "get":
            response = await client.request(method, scw_url, headers=scw_headers)
        else:
            response = await client.request(method, scw_url, headers=scw_headers, json=payload)

        logger.debug(f"Received response with status {response.status_code}: {response.json()}")

        if response.status_code >= 400:
            raise HTTPException(status_code=response.status_code, detail=response.json())

        return response

async def validate_aws_signature(request: Request):
    """
    Validates the AWS Signature for an incoming HTTP request.

    This method checks the Authorization header of the request for a valid
    AWS Signature Version 4 (SigV4) and ensures it matches the expected credentials
    and signing process. If the signature is invalid or missing, it raises an
    HTTPException with an appropriate status code.

    :param request: The HTTP request object containing headers and other details.
    :type request: Request

    :return: A dictionary containing verified AWS credentials including access key,
        region, and service information if the signature is valid.
    :rtype: dict

    :raises HTTPException: If the AWS signature is missing, invalid, or if there
        is a format error in the Authorization header.
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

    logger.info(match.groups())

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
    Handles incoming HTTP requests and provides functionality to proxy them, validate AWS signatures,
    and forward them to a Scaleway Secrets Manager for handling AWS Secrets Manager emulation. It
    parses the request, maps AWS Secrets Manager methods to Scaleway's API, and transforms
    Scaleway responses to their corresponding AWS equivalents.

    :param request: The incoming HTTP request object to be processed.
    :type request: Request
    :return: The response in AWS-compliant format if the request is successfully processed.
    :rtype: dict
    :raises HTTPException: If there are issues such as invalid AWS headers, unsupported methods,
                           or internal errors during request validation or forwarding.
    """

    method = request.method
    path = request.url.path
    headers = dict(request.headers)
    body = await request.body()

    logger.debug(f"Method: {method}")
    logger.debug(f"Path: {path}")
    logger.debug(f"Headers: {headers}")
    logger.debug(f"Body: {body}")

    # Retrieves AWS headers
    auth_header = request.headers.get("Authorization", "")
    if auth_header == "":
        logger.debug("Answering 200 OK on empty request")
        return {}

    # Validate AWS signature to ensure legitimacy
    try:
        aws_credentials = await validate_aws_signature(request)
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")

    aws_payload = await request.json()

    aws_method = headers["x-amz-target"]
    scw_main_response = None
    real_secret_id = None

    match aws_method:
        case "secretsmanager.CreateSecret":
            logger.info(f"Creating a Secret named {aws_payload['Name']} in {DEFAULT_SECRET_PATH}")

            # Create the Secret
            scw_secret_response = await forward_to_scaleway(
                method="post",
                path="",
                payload={
                    "name": aws_payload["Name"],
                    "project_id": SCW_PROJECT_ID,
                    "type": "opaque",
                    "protected": False,
                    "path": DEFAULT_SECRET_PATH,
                    "description": None
                },
                region=aws_credentials["region"],
                api_token=aws_credentials["access_key"]
            )
            scw_secret_data = scw_secret_response.json()

            if not scw_secret_data["id"]:
                raise HTTPException(status_code=500, detail=f"Secret created but wrong response format")

            base64_secret_content = base64.b64encode(aws_payload["SecretString"].encode("utf-8"))
            # Create a new version for the Secret containing sensitive data
            scw_main_response = await forward_to_scaleway(
                method="post",
                path=f"/{scw_secret_data["id"]}/versions",
                payload={
                    "data": base64_secret_content.decode() # cast to string
                },
                region=aws_credentials["region"],
                api_token=aws_credentials["access_key"]
            )
        case "secretsmanager.GetSecretValue":
            logger.info(f"Getting secret value of {aws_payload["SecretId"]}")

            # List Secrets to retrieve its id
            scw_list_response = await forward_to_scaleway(
                method="get",
                path=f"?project_id={SCW_PROJECT_ID}",
                payload={},
                region=aws_credentials["region"],
                api_token=aws_credentials["access_key"]
            )

            scw_list_data = scw_list_response.json()

            try:
                real_secret_id = cache_ids[aws_payload["SecretId"]]
                logger.info(f"Using cache to retrieve secret {aws_payload["SecretId"]} id.")
            except KeyError:
                logger.info(f"Fetching for the first time the id of secret {aws_payload["SecretId"]}.")
                for secret in scw_list_data["secrets"]:
                    if secret["name"] == aws_payload["SecretId"]:
                        real_secret_id = secret["id"]
                        cache_ids[aws_payload["SecretId"]] = real_secret_id

            if not real_secret_id:
                raise HTTPException(status_code=404)

            # Get the Secret latest version
            scw_main_response = await forward_to_scaleway(
                method="get",
                path=f"/{real_secret_id}/versions/latest_enabled/access?project_id={SCW_PROJECT_ID}",
                payload={},
                region=aws_credentials["region"],
                api_token=aws_credentials["access_key"]
            )
        case "secretsmanager.ListSecrets":
            logger.info(f"Listing secrets for project {SCW_PROJECT_ID}")

            scw_main_response = await forward_to_scaleway(
                method="get",
                path=f"?project_id={SCW_PROJECT_ID}",
                payload={},
                region=aws_credentials["region"],
                api_token=aws_credentials["access_key"]
            )

            # In case, we're adding secret ids to the cache.
            for secret in scw_main_response.json()["secrets"]:
                logger.info(f"Adding {secret["name"]} secret id to cache.")
                cache_ids[secret["name"]] = secret["id"]
        case _:
            raise HTTPException(status_code=405, detail=f"AWS method not allowed.")

    if not scw_main_response:
        raise HTTPException(status_code=500)

    scw_data = scw_main_response.json()
    aws_response = scw_data # By default

    # Map the Scaleway response to AWS response format
    match aws_method:
        case "secretsmanager.CreateSecret":
            aws_response = {
                "ARN": f"arn:aws:secretsmanager:{AWS_REGION}:{SCW_PROJECT_ID}:secret:{aws_payload["Name"]}",
                "Name": aws_payload["Name"],
                "VersionId": str(uuid.uuid4())
            }
        case "secretsmanager.GetSecretValue":
            # Get the Secret's metadata
            secret_metadata_response = await forward_to_scaleway(
                method="get",
                path=f"/{real_secret_id}?project_id={SCW_PROJECT_ID}",
                payload={},
                region=aws_credentials["region"],
                api_token=aws_credentials["access_key"]
            )
            secret_metadata_data = secret_metadata_response.json()
            aws_response = {
                "ARN": f"arn:aws:secretsmanager:{AWS_REGION}:{SCW_PROJECT_ID}:secret:{secret_metadata_data["name"]}",
                "Name": secret_metadata_data["name"],
                "CreatedDate": secret_metadata_data["created_at"],
                "SecretString": base64.b64decode(scw_data["data"]),
                "VersionId": str(uuid.uuid4()), # Generating a random uuid because revisions are integer in SCW.
                "VersionStages": ["AWSCURRENT"]
            }
        case "secretsmanager.ListSecrets":
            aws_response = {
                "SecretList": [
                    {
                        "ARN": f"arn:aws:secretsmanager:{AWS_REGION}:{SCW_PROJECT_ID}:secret:{secret["name"]}",
                        "Name": secret["name"],
                        "LastChangedDate": secret["updated_at"],
                        "LastAccessedDate": secret["updated_at"],
                        "Tags": secret["tags"],
                        "CreatedDate": secret["created_at"],
                        "PrimaryRegion": aws_credentials["region"],
                        "SecretVersionsToStages": {
                            f"{str(uuid.uuid4())}": ["AWSCURRENT"] # Generatin a random uuid because the only uuid is the SCW secret id, but it's not relevant here.
                        }
                    }
                    for secret in scw_data["secrets"]
                ],
                "NextToken": None
            }
        case _:
            # We shouldn't be in here.
            raise NotImplementedError(f"Unsupported operation")

    logger.debug(f"Answering to client: {aws_response}")

    return aws_response

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="debug" if debug else "info",
        log_config=logging_config
    )
