from fastapi import FastAPI, Request, HTTPException
import logging
import os
import uvicorn

from src.lib.aws.signature_validation import validate_aws_signature
from src.lib.scw_forwarder import ScalewayException
from src.methods.create_secret import CreateSecretMapper
from src.methods.get_secret_value import GetSecretValueMapper
from src.methods.list_secrets import ListSecretsMapper

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

@app.get("/")
@app.post("/")
async def proxy(request: Request):
    """
    Handles incoming HTTP requests through a proxy, processes them, and routes them to
    appropriate AWS Secrets Manager operations such as CreateSecret, GetSecretValue, or
    ListSecrets. Validates AWS request headers and signatures to ensure authenticity.

    :param request: The HTTP request object containing method, path, headers, and body
                    for processing.
    :type request: Request
    :return: Appropriate response data upon successful processing of the request. A
             dictionary is returned for valid operations, and HTTP exceptions are raised
             for unsupported methods or errors during processing.
    :rtype: dict
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
    auth_header = headers.get("authorization", "")
    if auth_header == "":
        logger.debug("Answering 200 OK on empty request for heartbeat")
        return {}

    # Validate AWS signature to ensure legitimacy
    try:
        aws_credentials = await validate_aws_signature(method, path, headers, body)
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")

    aws_payload = await request.json()

    aws_method = headers["x-amz-target"]

    try:
        match aws_method:
            case "secretsmanager.CreateSecret":
                logger.info(f"Creating a Secret named {aws_payload['Name']} in {DEFAULT_SECRET_PATH}")

                return await CreateSecretMapper(SCW_PROJECT_ID, DEFAULT_SECRET_PATH).proxy(aws_payload, aws_credentials)
            case "secretsmanager.GetSecretValue":
                logger.info(f"Getting secret value of {aws_payload["SecretId"]}")

                return await GetSecretValueMapper(SCW_PROJECT_ID, DEFAULT_SECRET_PATH).proxy(aws_payload, aws_credentials)
            case "secretsmanager.ListSecrets":
                logger.info(f"Listing secrets for project {SCW_PROJECT_ID}")

                return await ListSecretsMapper(SCW_PROJECT_ID, DEFAULT_SECRET_PATH).proxy(aws_payload, aws_credentials)
            case _:
                raise HTTPException(status_code=405, detail=f"{aws_method} method not supported.")
    except ScalewayException as e:
        logger.error(f"Scaleway error: {e.get_response()}")
        raise HTTPException(status_code=e.get_status_code(), detail=e.get_response())
    except Exception as e:
        logger.error(f"Internal error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="debug" if debug else "info",
        log_config=logging_config
    )
