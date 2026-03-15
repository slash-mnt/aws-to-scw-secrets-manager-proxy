import abc
from abc import ABCMeta

from src.lib.aws.credentials import Credentials

class Mapper(metaclass=ABCMeta):
    """
    Represents an abstract base class for mapping operations.

    This class serves as a blueprint for implementing specific
    mapping operations. It requires subclasses to define the
    `proxy` method, which is intended to handle specific
    mapping or transformation logic. The class initializes with
    project-specific identifiers and paths to ensure proper
    configuration for derived implementations.

    :ivar project_id: Identifier for the project associated with the mapper.
    :type project_id: str
    :ivar secret_path: Path to the secret or credential configuration for
        the mapper.
    :type secret_path: str
    """
    def __init__(self, project_id, secret_path):
        self.project_id = project_id
        self.secret_path = secret_path

    @abc.abstractmethod
    async def proxy(self, aws_payload: dict, aws_credentials: Credentials):
        """
        Summary:
        Abstract method that acts as a contract for proxying AWS requests. This method must be implemented in a derived
        class to define its specific behavior for sending AWS payloads while using the provided credentials. The implementation
        may include operations such as processing the payload, routing it to a service, and retrieving results.

        :param aws_payload: A dictionary containing the payload data that needs to be sent to an AWS service.
        :type aws_payload: dict

        :param aws_credentials: An instance of the `Credentials` class containing authentication details required to
            access AWS services.
        :type aws_credentials: Credentials

        :return: This is an abstract method and does not define a return value. The specific return type will be determined
            by the subclass implementation.
        """
        raise NotImplemented