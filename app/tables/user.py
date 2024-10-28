from pydantic import BaseModel

class User(BaseModel):
    """
    Model representing the session table configuration.

    Attributes:
        partition_key (str): The partition key for the session table.
        name (str): The name of the session table.
    """
    userId: str
    password: str
    email: str

class UserTable(BaseModel):
    """
    Model representing the user table configuration.

    Attributes:
        partition_key (str): The partition key for the user table.
        name (str): The name of the user table.
    """
    partition_key: str = "userId"
    name: str = "User"