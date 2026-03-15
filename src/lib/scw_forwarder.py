import httpx
import logging

logger = logging.getLogger(__name__)

class ScalewayException(Exception):
    """
    Exception raised for errors returned by Scaleway API.

    Represents an exception specifically designed for handling
    errors from the Scaleway API. It encapsulates both the HTTP
    status code and the response message, making it easier to
    handle these exceptions in a structured way.

    :ivar status_code: The HTTP status code returned by the Scaleway API.
    :type status_code: int
    :ivar response: The response message or data returned by the Scaleway API.
    :type response: Any
    """
    def __init__(self, status_code, response, *args):
        super(ScalewayException, self).__init__(status_code, response, args)

        self.status_code = status_code
        self.response = response

    def get_status_code(self):
        return self.status_code

    def get_response(self):
        return self.response


async def forward_to_scaleway(method: str, path: str, payload: dict, region: str, api_token: str):
    """
    Asynchronously forwards an HTTP request to the Scaleway Secret Manager API. This function constructs the
    appropriate request URL, sets required headers including authentication, and sends the request using
    the specified HTTP method. Responses are logged, and errors result in a ScalewayException being raised.

    :param method: The HTTP method to use for the request (e.g., "get", "post", "put", etc.).
    :param path: The API path to append to the base URL of the Scaleway Secret Manager.
    :param payload: The JSON payload to include in the request body (used for non-GET methods).
    :param region: The Scaleway region the request targets (e.g., "fr-par", "nl-ams").
    :param api_token: The Scaleway API token used for authenticating the request.
    :return: The full HTTP response object from the Scaleway API.
    :rtype: httpx.Response
    :raises ScalewayException: If the API responds with a status code >= 400.
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
            raise ScalewayException(response.status_code, response.json())

        return response