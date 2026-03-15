class Credentials:
    """
    Represents a set of credentials used for accessing a specific service in a
    given region.

    Provides methods to retrieve the access key, region, and service associated
    with the credentials.

    :ivar access_key: The access key identifier used for authentication.
    :type access_key: str
    :ivar region: The geographical region where the service is accessed.
    :type region: str
    :ivar service: The name of the service these credentials are for.
    :type service: str
    """
    def __init__(self, access_key, region, service, *args):
        self.access_key = access_key
        self.region = region
        self.service = service

    def get_access_key(self):
        return self.access_key

    def get_region(self):
        return self.region

    def get_service(self):
        return self.service