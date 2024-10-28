from env.ddb_client import get_ddb_client
from tables.user import UserTable, User
from boto3.dynamodb.conditions import Key
import bcrypt

class UserNotFound(Exception):
    """
    Exception raised when a user is not found in the database.
    """
    pass

class UserAlreadyExists(Exception):
    """
    Exception raised when attempting to create a user that already exists.
    """
    pass

class IncorrectPassword(Exception):
    """
    Exception raised when an incorrect password is provided.
    """
    pass


class UserRepository:
    """
    Repository class for managing users in DynamoDB.
    """

    def __init__(self) -> None:
        """
        Initialize the UserRepository instance.

        Sets up the user table and DynamoDB table.
        """
        self.user_table = UserTable()
        self.ddb_table = get_ddb_client().Table(self.user_table.name)

    def retrieve_user(self, user_id: str):
        """
        Retrieve a user from DynamoDB by user ID.

        Args:
            user_id (str): The ID of the user to retrieve.

        Returns:
            dict: The user data.

        Raises:
            UserNotFound: If the user is not found in the database.
        """
        try:
            return self.ddb_table.query(
                KeyConditionExpression=Key(self.user_table.partition_key).eq(str(user_id))
            )["Items"][0]
        except IndexError:
            raise UserNotFound()
    
    def check_if_user_exists(self, user_id: str) -> bool:
        """
        Check if a user exists in DynamoDB by user ID.

        Args:
            user_id (str): The ID of the user to check.

        Returns:
            bool: True if the user exists, False otherwise.
        """
        try:
            self.retrieve_user(user_id)
            return True
        except UserNotFound:
            return False
    
    def encrypt_password(self, password: str) -> bytes:
        """
        Encrypt a password using bcrypt.

        Args:
            password (str): The password to encrypt.

        Returns:
            bytes: The encrypted password.
        """
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode("utf-8"), salt)

    def create_user(self, body: dict) -> User:
        """
        Create a new user and store it in DynamoDB.

        Args:
            body (dict): The user data.

        Returns:
            User: The created user.

        Raises:
            UserAlreadyExists: If the user already exists in the database.
        """
        user = User(**body)

        if self.check_if_user_exists(user.userId):
            raise UserAlreadyExists()

        user.password = self.encrypt_password(user.password).decode('utf-8')

        self.ddb_table.put_item(Item=user.model_dump())

        return user

    def retrieve_user_if_password_is_correct(self, user_id: str, input_password: str) -> User:
        """
        Retrieve a user from DynamoDB if the provided password is correct.

        Args:
            user_id (str): The ID of the user to retrieve.
            input_password (str): The password to verify.

        Returns:
            User: The user data.

        Raises:
            IncorrectPassword: If the provided password is incorrect.
        """
        user_info = User(**self.retrieve_user(user_id))

        user_db_password = user_info.password.encode("utf-8")
        input_password = input_password.encode("utf-8")

        if not bcrypt.checkpw(input_password, user_db_password):
            raise IncorrectPassword()

        return user_info
