from pydantic import BaseModel

class User(BaseModel):
    userId: str
    password: str
    email: str

class UserTable(BaseModel):
    partition_key: str = "userId"
    name: str = "User"