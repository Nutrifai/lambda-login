from pydantic import BaseModel, ConfigDict

class Session(BaseModel):
    """
    Model representing a session.

    Attributes:
        sessionId (str): The unique identifier for the session.
        expireOn (int): The expiration timestamp for the session.
    """
    sessionId: str
    expireOn: int

    model_config = ConfigDict(
        extra='allow'
    )


class SessionTable(BaseModel):
    """
    Model representing the session table configuration.

    Attributes:
        partition_key (str): The partition key for the session table.
        name (str): The name of the session table.
    """
    partition_key: str = "sessionId"
    name: str = "Session"