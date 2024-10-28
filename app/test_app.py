import json
import unittest
from unittest.mock import patch, MagicMock
from lambda_function import lambda_handler
from repositories.session_repository import SessionRepository
from repositories.user_repository import UserRepository, UserNotFound, UserAlreadyExists, IncorrectPassword
from services.auth_service import AuthService, INTERNAL_SERVER_ERROR_RESPONSE

class TestLambdaFunction(unittest.TestCase):
    """
    Unit tests for the Lambda function.
    """

    @patch('lambda_function.AuthService')
    @patch('lambda_function.resolver')
    def test_login(self, mock_resolver, mock_auth_service):
        """
        Test the login functionality of the Lambda function.

        Args:
            mock_resolver: Mocked resolver.
            mock_auth_service: Mocked AuthService.

        Asserts:
            The response status code is 200.
        """
        mock_auth_service_instance = mock_auth_service.return_value
        mock_auth_service_instance.login.return_value = {"status": "success"}
        mock_resolver.resolve.return_value = {
            "statusCode": 200,
            "body": json.dumps({"message": "login successful"})
        }

        event = {
            "httpMethod": "POST",
            "path": "/login",
            "body": json.dumps({"userId": "test_user", "password": "test_pass"})
        }

        response = lambda_handler(event)

        self.assertEqual(response["statusCode"], 200)

    @patch('lambda_function.AuthService')
    @patch('lambda_function.resolver')
    def test_register(self, mock_resolver, mock_auth_service):
        """
        Test the register functionality of the Lambda function.

        Args:
            mock_resolver: Mocked resolver.
            mock_auth_service: Mocked AuthService.

        Asserts:
            The response status code is 200.
        """
        mock_auth_service_instance = mock_auth_service.return_value
        mock_auth_service_instance.register_user.return_value = {"status": "registered"}
        mock_resolver.resolve.return_value = {
            "statusCode": 200,
            "body": json.dumps({"message": "user registered"})
        }

        event = {
            "httpMethod": "POST",
            "path": "/register",
            "body": json.dumps({"userId": "new_user", "password": "new_pass"})
        }

        response = lambda_handler(event)

        self.assertEqual(response["statusCode"], 200)

    @patch('lambda_function.AuthService')
    @patch('lambda_function.resolver')
    def test_logout(self, mock_resolver, mock_auth_service):
        """
        Test the logout functionality of the Lambda function.

        Args:
            mock_resolver: Mocked resolver.
            mock_auth_service: Mocked AuthService.

        Asserts:
            The response status code is 200.
        """
        mock_auth_service_instance = mock_auth_service.return_value
        mock_auth_service_instance.logout.return_value = {"status": "logged_out"}
        mock_resolver.resolve.return_value = {
            "statusCode": 200,
            "body": json.dumps({"message": "logout successful"})
        }

        event = {
            "httpMethod": "POST",
            "path": "/logout",
            "headers": {"Cookie": "session_id=test_session"}
        }

        response = lambda_handler(event)

        self.assertEqual(response["statusCode"], 200)

class TestSessionRepository(unittest.TestCase):
    """
    Unit tests for the SessionRepository class.
    """

    @patch('repositories.session_repository.get_ddb_client')
    @patch('repositories.session_repository.SessionTable')
    def setUp(self, MockSessionTable, MockGetDdbClient):
        """
        Set up the test environment.

        Args:
            MockSessionTable: Mocked SessionTable.
            MockGetDdbClient: Mocked get_ddb_client.
        """
        self.mock_table = MockSessionTable.return_value
        self.mock_ddb_client = MockGetDdbClient.return_value
        self.mock_ddb_table = self.mock_ddb_client.Table.return_value
        self.repo = SessionRepository()

    @patch('repositories.session_repository.secrets.token_hex')
    @patch('repositories.session_repository.time')
    def test_create_session(self, mock_time, mock_token_hex):
        """
        Test the create_session method.

        Args:
            mock_time: Mocked time module.
            mock_token_hex: Mocked token_hex function.

        Asserts:
            The session ID is correct.
            The DynamoDB table put_item method is called once.
        """
        mock_time.return_value = 1000
        mock_token_hex.return_value = 'mock_session_id'
        session_content = {'user_id': '123'}

        session_id = self.repo.create_session(session_content)

        self.assertEqual(session_id, 'mock_session_id')
        self.mock_ddb_table.put_item.assert_called_once()
        args, kwargs = self.mock_ddb_table.put_item.call_args
        self.assertEqual(kwargs['Item']['sessionId'], 'mock_session_id')
        self.assertEqual(kwargs['Item']['expireOn'], 1000 + 8 * 60 * 60)
        self.assertEqual(kwargs['Item']['user_id'], '123')

    def test_delete_session(self):
        """
        Test the delete_session method.

        Asserts:
            The status code is 200.
            The DynamoDB table delete_item method is called once.
        """
        self.mock_ddb_table.delete_item.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
        session_id = 'mock_session_id'

        status_code = self.repo.delete_session(session_id)

        self.assertEqual(status_code, 200)
        self.mock_ddb_table.delete_item.assert_called_once_with(Key={self.mock_table.partition_key: session_id})

class TestUserRepository(unittest.TestCase):
    """
    Unit tests for the UserRepository class.
    """

    @patch('repositories.user_repository.get_ddb_client')
    @patch('repositories.user_repository.UserTable')
    def setUp(self, MockUserTable, MockGetDdbClient):
        """
        Set up the test environment.

        Args:
            MockUserTable: Mocked UserTable.
            MockGetDdbClient: Mocked get_ddb_client.
        """
        self.mock_table = MockUserTable.return_value
        self.mock_ddb_client = MockGetDdbClient.return_value
        self.mock_ddb_table = self.mock_ddb_client.Table.return_value
        self.repo = UserRepository()

    def test_retrieve_user(self):
        """
        Test the retrieve_user method.

        Asserts:
            The user data is correct.
        """
        self.mock_ddb_table.query.return_value = {"Items": [{"userId": "123", "password": "hashed_password"}]}
        user_id = "123"

        user = self.repo.retrieve_user(user_id)

        self.assertEqual(user["userId"], "123")
        self.assertEqual(user["password"], "hashed_password")

    def test_retrieve_user_not_found(self):
        """
        Test the retrieve_user method when the user is not found.

        Asserts:
            UserNotFound exception is raised.
        """
        self.mock_ddb_table.query.return_value = {"Items": []}
        user_id = "123"

        with self.assertRaises(UserNotFound):
            self.repo.retrieve_user(user_id)

    def test_check_if_user_exists(self):
        """
        Test the check_if_user_exists method.

        Asserts:
            The user exists.
        """
        self.mock_ddb_table.query.return_value = {"Items": [{"userId": "123"}]}
        user_id = "123"

        exists = self.repo.check_if_user_exists(user_id)

        self.assertTrue(exists)

    def test_check_if_user_does_not_exist(self):
        """
        Test the check_if_user_exists method when the user does not exist.

        Asserts:
            The user does not exist.
        """
        self.mock_ddb_table.query.return_value = {"Items": []}
        user_id = "123"

        exists = self.repo.check_if_user_exists(user_id)

        self.assertFalse(exists)

    @patch('repositories.user_repository.bcrypt')
    def test_encrypt_password(self, mock_bcrypt):
        """
        Test the encrypt_password method.

        Args:
            mock_bcrypt: Mocked bcrypt module.

        Asserts:
            The password is encrypted correctly.
        """
        mock_bcrypt.gensalt.return_value = b'salt'
        mock_bcrypt.hashpw.return_value = b'hashed_password'
        password = "password"

        hashed_password = self.repo.encrypt_password(password)

        self.assertEqual(hashed_password, b'hashed_password')
        mock_bcrypt.gensalt.assert_called_once()
        mock_bcrypt.hashpw.assert_called_once_with(password.encode("utf-8"), b'salt')

    @patch('repositories.user_repository.bcrypt')
    def test_create_user(self, mock_bcrypt):
        """
        Test the create_user method.

        Args:
            mock_bcrypt: Mocked bcrypt module.

        Asserts:
            The user is created correctly.
        """
        mock_bcrypt.gensalt.return_value = b'salt'
        mock_bcrypt.hashpw.return_value = b'hashed_password'
        body = {"userId": "123", "password": "password", "email": "user@gmail.com"}

        self.mock_ddb_table.query.return_value = {"Items": []}

        user = self.repo.create_user(body)

        self.assertEqual(user.userId, "123")
        self.assertEqual(user.password, b"hashed_password".decode('utf-8'))
        self.mock_ddb_table.put_item.assert_called_once()
        args, kwargs = self.mock_ddb_table.put_item.call_args
        self.assertEqual(kwargs['Item']['userId'], "123")
        self.assertEqual(kwargs['Item']['password'], b"hashed_password".decode('utf-8'))
        self.assertEqual(kwargs['Item']['email'], "user@gmail.com")

    def test_create_user_already_exists(self):
        """
        Test the create_user method when the user already exists.

        Asserts:
            UserAlreadyExists exception is raised.
        """
        body = {"userId": "123", "password": "password", "email": "user@gmail.com"}

        self.mock_ddb_table.query.return_value = {"Items": [{"userId": "123"}]}

        with self.assertRaises(UserAlreadyExists):
            self.repo.create_user(body)

    @patch('repositories.user_repository.bcrypt')
    def test_retrieve_user_if_password_is_correct(self, mock_bcrypt):
        """
        Test the retrieve_user_if_password_is_correct method.

        Args:
            mock_bcrypt: Mocked bcrypt module.

        Asserts:
            The user data is correct.
        """
        mock_bcrypt.checkpw.return_value = True
        self.mock_ddb_table.query.return_value = {"Items": [{"userId": "123", "password": "hashed_password", "email": "user@gmail.com"}]}
        user_id = "123"
        input_password = "password"

        user = self.repo.retrieve_user_if_password_is_correct(user_id, input_password)

        self.assertEqual(user.userId, "123")
        self.assertEqual(user.password, "hashed_password")
        mock_bcrypt.checkpw.assert_called_once_with(input_password.encode("utf-8"), "hashed_password".encode("utf-8"))

    @patch('repositories.user_repository.bcrypt')
    def test_retrieve_user_if_password_is_incorrect(self, mock_bcrypt):
        """
        Test the retrieve_user_if_password_is_correct method when the password is incorrect.

        Asserts:
            IncorrectPassword exception is raised.
        """
        mock_bcrypt.checkpw.return_value = False
        self.mock_ddb_table.query.return_value = {"Items": [{"userId": "123", "password": "hashed_password", "email": "user@gmail.com"}]}
        user_id = "123"
        input_password = "hashed_password"

        with self.assertRaises(IncorrectPassword):
            self.repo.retrieve_user_if_password_is_correct(user_id, input_password)

class TestAuthService(unittest.TestCase):
    """
    Unit tests for the AuthService class.
    """

    @patch('repositories.user_repository.get_ddb_client')
    @patch('services.auth_service.SessionRepository')
    @patch('services.auth_service.UserRepository')
    def setUp(self, MockUserRepository, MockSessionRepository, MockGetDdbClient):
        """
        Set up the test environment.

        Args:
            MockUserRepository: Mocked UserRepository.
            MockSessionRepository: Mocked SessionRepository.
            MockGetDdbClient: Mocked get_ddb_client.
        """
        self.mock_user_repo = MockUserRepository.return_value
        self.mock_session_repo = MockSessionRepository.return_value
        self.mock_ddb_client = MockGetDdbClient.return_value
        self.mock_ddb_table = self.mock_ddb_client.Table.return_value
        self.auth_service = AuthService()

    def test_register_user_success(self):
        """
        Test the register_user method for successful registration.

        Asserts:
            The response status code is 200.
            The Set-Cookie header is present in the response.
        """
        body = {"userId": "123", "password": "password", "email": "user@gmail.com"}
        mock_user = MagicMock()
        self.mock_user_repo.create_user.return_value = mock_user
        self.mock_session_repo.create_session.return_value = 'mock_session_id'

        response = self.auth_service.register_user(body)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Set-Cookie", response.headers)

    def test_register_user_already_exists(self):
        """
        Test the register_user method when the user already exists.

        Asserts:
            The response status code is 400.
            The error message is correct.
        """
        body = {"userId": "123", "password": "password", "email": "user@gmail.com"}
        self.mock_user_repo.create_user.side_effect = UserAlreadyExists

        response = self.auth_service.register_user(body)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.body["error_message"], "Já existe um usuário com esse ID Usuário!")

    def test_register_user_unknown_error(self):
        """
        Test the register_user method when an unknown error occurs.

        Asserts:
            The response status code is 500.
            The error message is correct.
        """
        body = {"invalid": "json"}
        self.mock_user_repo.create_user.side_effect = Exception("Unknown error")

        response = self.auth_service.register_user(body)

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.body, INTERNAL_SERVER_ERROR_RESPONSE.body)

    def test_login_success(self):
        """
        Test the login method for successful login.

        Asserts:
            The response status code is 200.
            The Set-Cookie header is present in the response.
        """
        user_id = "123"
        input_password = "password"
        mock_user = MagicMock()
        self.mock_user_repo.retrieve_user_if_password_is_correct.return_value = mock_user
        self.mock_session_repo.create_session.return_value = 'mock_session_id'

        response = self.auth_service.login(user_id, input_password)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Set-Cookie", response.headers)

    def test_login_user_not_found(self):
        """
        Test the login method when the user is not found.

        Asserts:
            The response status code is 401.
            The error message is correct.
        """
        user_id = "123"
        input_password = "password"
        self.mock_user_repo.retrieve_user_if_password_is_correct.side_effect = UserNotFound

        response = self.auth_service.login(user_id, input_password)

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.body["error_message"], "Usuário não encontrado!")

    def test_login_incorrect_password(self):
        """
        Test the login method when the password is incorrect.

        Asserts:
            The response status code is 401.
            The error message is correct.
        """
        user_id = "123"
        input_password = "password"
        self.mock_user_repo.retrieve_user_if_password_is_correct.side_effect = IncorrectPassword

        response = self.auth_service.login(user_id, input_password)

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.body["error_message"], "Senha inválida!")

    def test_logout_success(self):
        """
        Test the logout method for successful logout.

        Asserts:
            The response status code is 200.
            The Set-Cookie header is present in the response.
        """
        self.mock_ddb_table.query.return_value = {"Items": [{"sessionId": "mock_session_id", "email": "user@gmail.com", "expireOn": "1730071196", "userId": "123"}]}
        cookies = {"sessionId": "mock_session_id"}
        self.mock_session_repo.delete_session.return_value = 200

        response = self.auth_service.logout(cookies)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Set-Cookie", response.headers)

    def test_logout_no_session(self):
        """
        Test the logout method when there is no session.

        Asserts:
            The response status code is 400.
            The error message is correct.
        """
        cookies = {}

        response = self.auth_service.logout(cookies)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.body["error_message"], "Usuário não está logado")

    def test_logout_unknown_error(self):
        """
        Test the logout method when an unknown error occurs.

        Asserts:
            The response status code is 500.
            The error message is correct.
        """
        cookies = { "sessionId": "mock_session_id" }
        self.mock_session_repo.delete_session.return_value = 500

        response = self.auth_service.logout(cookies)

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.body, INTERNAL_SERVER_ERROR_RESPONSE.body)