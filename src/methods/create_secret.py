import base64
import logging
import os
import uuid

from src.lib.aws.credentials import Credentials
from src.lib.scw_forwarder import forward_to_scaleway, ScalewayException
from src.methods.mapper import Mapper

logger = logging.getLogger(__name__)
AWS_REGION = os.getenv("AWS_REGION", "eu-west-3")

class CreateSecretMapper(Mapper):
    """
    Maps AWS CreateSecret requests to Scaleway's Secrets Manager and forwards the request via API calls.

    This class is used to handle the functionality of mapping and creating secrets in Scaleway's Secrets
    Manager when triggered by a CreateSecret operation from AWS Secrets Manager. It processes the AWS
    payload, communicates with the Scaleway API to create and manage secrets, and handles any inconsistencies
    in the response format.

    :ivar project_id: The project ID associated with Scaleway where the secret will be created.
    :type project_id: str
    :ivar secret_path: The path in the Scaleway Secrets Manager under which the secret will be stored.
    :type secret_path: str
    """

    async def proxy(self, aws_payload: dict, aws_credentials: Credentials):
        """
        Maps and forwards the creation of an AWS secret to the Scaleway Secrets Manager. The method creates a secret
        in Scaleway configured with details from `aws_payload`, along with creating a new version containing
        sensitive data. The corresponding information is then returned in an AWS-compatible format.

        :param aws_payload: Dictionary containing the payload for secret creation in AWS format. It must
            include keys such as "Name" and "SecretString".
        :type aws_payload: dict

        :param aws_credentials: Object containing credentials and metadata to interact with AWS resources.
        :type aws_credentials: Credentials

        :return: Dictionary representing the created secret in AWS-compatible format. Keys include:
            "ARN" - The Amazon Resource Name (ARN) of the secret.
            "Name" - The name of the secret.
            "VersionId" - A randomly generated UUID representing the version of the secret.
        :rtype: dict
        """
        logger.info(f"Mapping CreateSecret for {aws_payload["Name"]} secret in project {self.project_id} ({aws_credentials.get_region()})")

        scw_secret_data = (await forward_to_scaleway(
            method="post",
            path="",
            payload={
                "name": aws_payload["Name"],
                "project_id": self.project_id,
                "type": "opaque",
                "protected": False,
                "path": self.secret_path,
                "description": None
            },
            region=aws_credentials.get_region(),
            api_token=aws_credentials.get_access_key()
        )).json()

        if not scw_secret_data["id"]:
            raise ScalewayException(500, "Secret created but wrong response format")

        base64_secret_content = base64.b64encode(aws_payload["SecretString"].encode("utf-8"))

        # Create a new version for the Secret containing sensitive data
        response = (await forward_to_scaleway(
            method="post",
            path=f"/{scw_secret_data["id"]}/versions",
            payload={
                "data": base64_secret_content.decode()  # cast to string
            },
            region=aws_credentials.get_region(),
            api_token=aws_credentials.get_access_key()
        )).json()

        return {
            "ARN": f"arn:aws:secretsmanager:{AWS_REGION}:{self.project_id}:secret:{aws_payload["Name"]}",
            "Name": aws_payload["Name"],
            "VersionId": str(uuid.uuid4())
        }