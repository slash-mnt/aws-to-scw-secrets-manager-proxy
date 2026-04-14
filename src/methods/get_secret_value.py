import base64
import logging
import uuid

from src.lib.aws.credentials import Credentials
from src.lib.scw_forwarder import forward_to_scaleway, ScalewayException
from src.methods.mapper import Mapper

logger = logging.getLogger(__name__)

# Use a small cache object to store secret ids, avoiding listing secrets everytime.
# Secret names are unique within a project.
# Cache keys are the secret name, values are their ids.
cache_ids = {}

class GetSecretValueMapper(Mapper):
    """
    Represents a mapper for the GetSecretValue operation, which proxies requests to Scaleway's Secrets
    Manager while preserving the behavior of AWS Secrets Manager. It facilitates retrieving secrets and
    returning the corresponding metadata in an AWS-compatible format.

    This mapper ensures compatibility between AWS Secrets Manager and Scaleway's Secrets Manager by
    translating requests and responses.

    :ivar project_id: The identifier of the project in Scaleway's environment within which secrets are
        managed.
    :type project_id: str
    """

    async def proxy(self, aws_payload: dict, aws_credentials: Credentials):
        """
        This asynchronous method proxies a GetSecretValue operation to Scaleway's Secrets Manager,
        mimicking the behavior of AWS Secrets Manager. It fetches the secret identified by its
        name from the Scaleway environment based on the provided AWS credentials and payload.

        :param aws_payload: The payload for the request containing the identifier of the secret
            (e.g., 'SecretId') needed to retrieve the secret.
        :type aws_payload: dict
        :param aws_credentials: Credentials necessary for authenticating with the AWS-style
            proxy to communicate with Scaleway's Secrets Manager.
        :type aws_credentials: Credentials
        :return: A dictionary containing secret metadata and the retrieved secret string in a format
            similar to AWS Secrets Manager's GetSecretValue response. This includes ARN, name,
            creation date, secret string, version ID, and version stages.
        :rtype: dict
        :raises ScalewayException: If the secret is not found in the Scaleway project.

        """
        logger.info(f"Mapping GetSecretValue for {aws_payload["SecretId"]} secret in project {self.project_id} ({aws_credentials.get_region()})")

        real_secret_id = None

        try:
            real_secret_id = cache_ids[aws_payload["SecretId"]]
            logger.info(f"Using cache to retrieve secret {aws_payload["SecretId"]} id.")
        except KeyError:
            logger.info(f"Fetching the id of secret {aws_payload["SecretId"]}.")

            # List Secrets to retrieve its id
            scw_list_data = (await forward_to_scaleway(
                method="get",
                path=f"?project_id={self.project_id}",
                payload={},
                region=aws_credentials.get_region(),
                api_token=aws_credentials.get_access_key()
            )).json()

            for secret in scw_list_data["secrets"]:
                if secret["name"] == aws_payload["SecretId"]:
                    logger.info(f"Setting {secret["id"]} in cache for {aws_payload["SecretId"]} secret")
                    real_secret_id = secret["id"]
                    cache_ids[aws_payload["SecretId"]] = real_secret_id

        if not real_secret_id:
            raise ScalewayException(404, f"Secret {aws_payload["SecretId"]} not found in project {self.project_id}")

        # Get the Secret latest enabled version
        secret = (await forward_to_scaleway(
            method="get",
            path=f"/{real_secret_id}/versions/latest_enabled/access?project_id={self.project_id}",
            payload={},
            region=aws_credentials.get_region(),
            api_token=aws_credentials.get_access_key()
        )).json()

        # Get the Secret's metadata
        metadata = (await forward_to_scaleway(
            method="get",
            path=f"/{real_secret_id}?project_id={self.project_id}",
            payload={},
            region=aws_credentials.get_region(),
            api_token=aws_credentials.get_access_key()
        )).json()

        return {
            "ARN": f"arn:aws:secretsmanager:{aws_credentials.get_region()}:{self.project_id}:secret:{metadata["name"]}",
            "Name": metadata["name"],
            "CreatedDate": metadata["created_at"],
            "SecretString": base64.b64decode(secret["data"]),
            "VersionId": str(uuid.uuid4()),  # Generating a random uuid because revisions are integer in SCW.
            "VersionStages": ["AWSCURRENT"]
        }