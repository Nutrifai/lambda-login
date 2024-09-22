from env.ddb_client import get_ddb_client
from tables.session import SessionTable, Session
from time import time
import secrets

HOUR_IN_SECONDS = 60 * 60
SESSION_DURATION_IN_HOURS = 8
SESSION_ID_BYTES_LENGTH = 16

class SessionRepository:

    def __init__(self) -> None:
        self.session_table = SessionTable()
        self.ddb_table = get_ddb_client().Table(self.session_table.name)

    def __generate_expire_on(self, hours: int) -> int:
        return int(time()) + (HOUR_IN_SECONDS * hours)

    def create_session(self, session_content: dict) -> str:
        session_id = secrets.token_hex(SESSION_ID_BYTES_LENGTH)
        expire_on = self.__generate_expire_on(SESSION_DURATION_IN_HOURS)

        session = Session(sessionId=session_id, expireOn=expire_on, **session_content)
        
        self.ddb_table.put_item(Item=session.model_dump())

        return session_id
    
    def delete_session(self, session_id: str):
        delete_response = self.ddb_table.delete_item(Key={self.session_table.partition_key: session_id})
        operation_status = delete_response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return operation_status