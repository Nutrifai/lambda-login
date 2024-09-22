from pydantic import BaseModel, ConfigDict

class Session(BaseModel):
    sessionId: str
    expireOn: int

    model_config = ConfigDict(
        extra='allow'
    )


class SessionTable(BaseModel):
    partition_key: str = "sessionId"
    name: str = "Session"