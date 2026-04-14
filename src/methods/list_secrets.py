import logging
import uuid

from src.lib.aws.credentials import Credentials
from src.lib.scw_forwarder import forward_to_scaleway
from src.methods.mapper import Mapper

logger = logging.getLogger(__name__)

class ListSecretsMapper(Mapper):
    """
    Mapper class for handling the ListSecrets operation.

    This class is responsible for mapping the ListSecrets operation by
    forwarding requests to Scaleway's API. It constructs the response
    to resemble an AWS Secrets Manager response for compatibility
    purposes.

    :ivar project_id: The identifier of the project being processed.
    :type project_id: str
    """

    async def proxy(self, aws_payload: dict, aws_credentials: Credentials):
        """
        Proxies a request to retrieve secrets from Scaleway and maps them into an AWS-compatible
        response format for the `ListSecrets` method in AWS Secrets Manager.

        :param aws_payload: AWS payload data for the request.
        :type aws_payload: dict
        :param aws_credentials: Credentials object containing the AWS region and API token.
        :type aws_credentials: Credentials
        :return: A dictionary representing the AWS-compatible response that contains a list of
            secrets and additional metadata such as tags, creation dates, and stages of secret versions.
        :rtype: dict
        """
        logger.info(f"Mapping ListSecrets method in project {self.project_id} ({aws_credentials.region})")

        secrets = (await forward_to_scaleway(
            method="get",
            path=f"?project_id={self.project_id}",
            payload={},
            region=aws_credentials.get_region(),
            api_token=aws_credentials.get_access_key()
        )).json()

        return {
            "SecretList": [
                {
                    "ARN": f"arn:aws:secretsmanager:{aws_credentials.get_region()}:{self.project_id}:secret:{secret["name"]}",
                    "Name": secret["name"],
                    "LastChangedDate": secret["updated_at"],
                    "LastAccessedDate": secret["updated_at"],
                    "Tags": secret["tags"],
                    "CreatedDate": secret["created_at"],
                    "PrimaryRegion": aws_credentials.get_region(),
                    "SecretVersionsToStages": {
                        f"{str(uuid.uuid4())}": ["AWSCURRENT"] # Generating a random uuid because the only uuid is the SCW secret id, but it's not relevant here.
                    }
                }
                for secret in secrets["secrets"]
            ],
            "NextToken": None
        }