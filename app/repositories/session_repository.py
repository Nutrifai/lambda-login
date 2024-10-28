from env.ddb_client import get_ddb_client
from tables.session import SessionTable, Session
from time import time
import secrets

# Constants for time calculations and session ID length
HOUR_IN_SECONDS = 60 * 60
SESSION_DURATION_IN_HOURS = 8
SESSION_ID_BYTES_LENGTH = 16

class SessionRepository:
    """
    Repository class for managing sessions in DynamoDB.
    """

    def __init__(self) -> None:
        """
        Initialize the SessionRepository instance.

        Sets up the session table and DynamoDB table.
        """
        self.session_table = SessionTable()
        self.ddb_table = get_ddb_client().Table(self.session_table.name)

    def __generate_expire_on(self, hours: int) -> int:
        """
        Generate the expiration timestamp for a session.

        Args:
            hours (int): Number of hours until the session expires.

        Returns:
            int: Expiration timestamp in seconds since epoch.
        """
        return int(time()) + (HOUR_IN_SECONDS * hours)

    def create_session(self, session_content: dict) -> str:
        """
        Create a new session and store it in DynamoDB.

        Args:
            session_content (dict): Content of the session to be stored.

        Returns:
            str: The generated session ID.
        """
        session_id = secrets.token_hex(SESSION_ID_BYTES_LENGTH)
        expire_on = self.__generate_expire_on(SESSION_DURATION_IN_HOURS)

        session = Session(sessionId=session_id, expireOn=expire_on, **session_content)
        
        self.ddb_table.put_item(Item=session.model_dump())

        return session_id
    
    def delete_session(self, session_id: str):
        """
        Delete a session from DynamoDB.

        Args:
            session_id (str): The ID of the session to be deleted.

        Returns:
            int: HTTP status code of the delete operation.
        """
        delete_response = self.ddb_table.delete_item(Key={self.session_table.partition_key: session_id})
        operation_status = delete_response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return operation_status