from aws_lambda_powertools.event_handler import Response
from repositories.user_repository import UserRepository, UserNotFound, IncorrectPassword, UserAlreadyExists
from repositories.session_repository import SessionRepository, SESSION_DURATION_IN_HOURS, HOUR_IN_SECONDS
from tables.user import User
from pydantic import ValidationError

# Name of the cookie used for session management
COOKIE_NAME = "sessionId"

# Template for the session cookie
SESSION_COOKIE = f"{COOKIE_NAME}=%(session)s; HttpOnly; SameSite=Strict; Path=/; Secure; Max-Age=%(max_age)s"

# Response for internal server errors
INTERNAL_SERVER_ERROR_RESPONSE = Response(status_code=500, body={"error_message": "Um erro desconhecido aconteceu, tente novamente em breve!"})

class AuthService:
    """
    Service class for handling authentication-related operations.
    """

    def __init__(self):
        """
        Initialize the AuthService instance.

        Sets up the user repository and session repository.
        """
        self.user_repository = UserRepository()
        self.session_resository = SessionRepository()

    def __success_response(self, user: User):
        """
        Generate a successful response with a session cookie.

        Args:
            user (User): The user object.

        Returns:
            Response: The HTTP response with a session cookie.
        """
        user_content = user.model_dump()
        user_content.pop("password")
        
        session_id = self.session_resository.create_session(user_content)

        return Response(
            status_code=200,
            body={},
            headers={
                "Set-Cookie": SESSION_COOKIE % {"session": session_id, "max_age": SESSION_DURATION_IN_HOURS * HOUR_IN_SECONDS}
            }
        )
    
    def register_user(self, body: dict) -> Response:
        """
        Register a new user.

        Args:
            body (dict): The user data.

        Returns:
            Response: The HTTP response indicating the result of the registration.
        """
        error_response = INTERNAL_SERVER_ERROR_RESPONSE

        try:
            created_user = self.user_repository.create_user(body)

        except ValidationError as err:
            error_response = Response(
                status_code=400,
                body={
                    "error_message": "Confira os campos e tente novamente!"
                }
            )
            raise err
        
        except UserAlreadyExists:
            return Response(
                status_code=400,
                body={
                    "error_message": "Já existe um usuário com esse ID Usuário!"
                }
            )

        except Exception as err:
            print(err)
            return error_response

        return self.__success_response(created_user)

    def login(self, user_id: str, input_password: str) -> Response:
        """
        Log in a user.

        Args:
            user_id (str): The user ID.
            input_password (str): The user's password.

        Returns:
            Response: The HTTP response indicating the result of the login attempt.
        """
        try:
            user_info = self.user_repository.retrieve_user_if_password_is_correct(user_id, input_password)
        except UserNotFound:
            return Response(
                status_code=401,
                body={
                    "error_message": "Usuário não encontrado!"
                }
            )
        except IncorrectPassword:
            return Response(
                status_code=401,
                body={
                    "error_message": "Senha inválida!"
                }
            )
        
        return self.__success_response(user_info)
    
    def logout(self, cookies: dict):
        """
        Log out a user.

        Args:
            cookies (dict): The cookies from the request.

        Returns:
            Response: The HTTP response indicating the result of the logout attempt.
        """
        print('cookies')
        print(cookies)
        session_id = cookies.get(COOKIE_NAME)

        if not session_id:
            return Response(
            status_code=400,
            body={
                "error_message": "Usuário não está logado"
            },
        )

        operation_status_code = self.session_resository.delete_session(session_id=session_id)
        
        if operation_status_code != 200:
            return INTERNAL_SERVER_ERROR_RESPONSE
        
        return Response(
            status_code=200,
            body={},
            headers={
                "Set-Cookie": SESSION_COOKIE % {"session": "deleted", "max_age": -1}
            }
        )