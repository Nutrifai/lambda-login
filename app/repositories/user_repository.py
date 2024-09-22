from env.ddb_client import get_ddb_client
from tables.user import UserTable, User
from boto3.dynamodb.conditions import Key
import bcrypt

class UserNotFound(Exception):
    pass

class UserAlreadyExists(Exception):
    pass

class IncorrectPassword(Exception):
    pass


class UserRepository:

    def __init__(self) -> None:
        self.user_table = UserTable()
        self.ddb_table = get_ddb_client().Table(self.user_table.name)

    def retrieve_user(self, user_id: str):
        try:
            return self.ddb_table.query(
                KeyConditionExpression=Key(self.user_table.partition_key).eq(str(user_id))
            )["Items"][0]
        except IndexError:
            raise UserNotFound()
    
    def check_if_user_exists(self, user_id: str) -> bool:
        try:
            self.retrieve_user(user_id)
            return True
        except UserNotFound:
            return False
    
    def encrypt_password(self, password: str) -> bytes:
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode("utf-8"), salt)
        
    def create_user(self, body: dict) -> User:
        user = User(**body)

        if self.check_if_user_exists(user.userId):
            raise UserAlreadyExists()

        user.password = self.encrypt_password(user.password).decode('utf-8')

        self.ddb_table.put_item(Item=user.model_dump())

        return user

    def retrieve_user_if_password_is_correct(self, user_id: str, input_password: str) -> User:
        user_info = User(**self.retrieve_user(user_id))
        
        user_db_password = user_info.password.encode("utf-8")
        input_password = input_password.encode("utf-8")

        if not bcrypt.checkpw(input_password, user_db_password):
            raise IncorrectPassword()
        
        return user_info
 