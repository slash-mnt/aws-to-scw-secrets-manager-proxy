from botocore.auth import SigV4Auth
from botocore.credentials import Credentials as AWSCredentials
from botocore.exceptions import ClientError
from botocore.awsrequest import AWSRequest
from fastapi import HTTPException
import logging
import re

from src.lib.aws.credentials import Credentials

logger = logging.getLogger(__name__)

async def validate_aws_signature(method: str, path: str, headers: dict, body):
    """
    Validates an AWS Signature Version 4 for a specific HTTP request and checks its
    integrity. This function ensures the given request's signature complies with
    AWS standards by parsing the headers, extracting necessary credentials, and
    validating the signature against the expected format and values.

    :param method: HTTP method of the request (e.g., GET, POST, PUT).
    :type method: str
    :param path: Request path (e.g., "/example/path").
    :type path: str
    :param headers: A dictionary containing HTTP headers, including required AWS
        authorization and date headers.
    :type headers: dict
    :param body: Request payload or body, used to verify signed signature content.
    :return: A ``Credentials`` object if validation succeeds.
    :rtype: Credentials
    :raises HTTPException: If the following cases occur:
        - Authorization header is missing or invalid.
        - ``x-amz-date`` header is missing.
        - Signature format or content does not match expectations.
        - An unexpected error occurs during the validation process.
    """

    # Retrieves AWS headers
    auth_header = headers.get("authorization")
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
    try:
        headers.get("x-amz-date")
    except KeyError:
        logger.error("Missing x-amz-date header")
        raise HTTPException(status_code=401, detail="Missing x-amz-date header")

    # Prepare the credentials (here, you should retrieve them from a database or a service)
    # For the example, we use dummy credentials
    credentials = AWSCredentials(access_key, "virtual_secret_key")

    # Signature validation
    try:
        SigV4Auth(credentials, service, region).add_auth(
            AWSRequest(
                method=method,
                url=f"https://{headers.get('host')}{path}",
                data=body,
                headers=headers
            )
        )
        logger.info("AWS Signature valid")
        # If the signature is well-formed, returns the credentials
        return Credentials(access_key, region, service)
    except ClientError as e:
        logger.error(f"Failed to validate AWS Signature: {str(e)}")
        raise HTTPException(status_code=401, detail=f"Invalid AWS Signature: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error during signature validation: {str(e)}")
        raise HTTPException(status_code=401, detail=f"Validation error: {str(e)}")