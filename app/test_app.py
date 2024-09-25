import pytest
import json
from unittest.mock import patch, MagicMock
from lambda_function import lambda_handler, __setup_services


@pytest.fixture
def mock_auth_service(mocker):
    """
    Fixture para simular o serviço de autenticação (AuthService).
    
    :param mocker: Um objeto do pytest-mock que permite criar mocks.
    :return: Um mock do AuthService.
    """
    mock_service = mocker.patch('lambda_function.AuthService')
    return mock_service


@pytest.fixture
def mock_resolver(mocker):
    """
    Fixture para simular o resolver da API Gateway.
    
    :param mocker: Um objeto do pytest-mock que permite criar mocks.
    :return: Um mock do resolver.
    """
    return mocker.patch('lambda_function.resolver')


def test_setup_services_initializes_auth_service(mock_auth_service):
    """
    Testa se o serviço de autenticação (AuthService) é inicializado corretamente.
    
    Chama a função __setup_services e verifica se o AuthService foi instanciado.
    """
    __setup_services()
    mock_auth_service.assert_called_once()


def test_login_success(mock_auth_service, mock_resolver):
    """
    Testa o fluxo de login bem-sucedido.
    
    Simula uma requisição de login e verifica se a resposta retornada está correta.
    """
    event = {
        "body": json.dumps({"userId": "testuser", "password": "testpass"}),
        "httpMethod": "POST",
        "path": "/login"
    }

    # Configura o retorno esperado do método de login
    mock_auth_service.login.return_value = {"message": "login successful"}

    # Mock da resposta do resolver
    mock_resolver.resolve.return_value = {
        "statusCode": 200,
        "body": json.dumps({"message": "login successful"})
    }
    
    response = lambda_handler(event)

    # Transforma a resposta do corpo
    response_body = json.loads(response["body"])
    assert response_body["message"] == "login successful"


def test_register_user_success(mock_auth_service, mock_resolver):
    """
    Testa o fluxo de registro de usuário bem-sucedido.
    
    Simula uma requisição de registro e verifica se a resposta retornada está correta.
    """
    event = {
        "body": json.dumps({"userId": "newuser", "password": "newpass"}),
        "httpMethod": "POST",
        "path": "/register"
    }

    # Configura o retorno esperado do método de registro
    mock_auth_service.register_user.return_value = {"message": "user registered"}

    # Mock da resposta do resolver
    mock_resolver.resolve.return_value = {
        "statusCode": 200,
        "body": json.dumps({"message": "user registered"})
    }
    
    response = lambda_handler(event)

    # Transforma a resposta do corpo
    response_body = json.loads(response["body"])
    assert response_body["message"] == "user registered"


def test_logout_success(mock_auth_service, mock_resolver):
    """
    Testa o fluxo de logout bem-sucedido.
    
    Simula uma requisição de logout e verifica se a resposta retornada está correta.
    """
    event = {
        "headers": {"Cookie": "session_id=abc123"},
        "httpMethod": "POST",
        "path": "/logout"
    }

    # Configura o retorno esperado do método de logout
    mock_auth_service.logout.return_value = {"message": "logout successful"}

    # Mock da resposta do resolver
    mock_resolver.resolve.return_value = {
        "statusCode": 200,
        "body": json.dumps({"message": "logout successful"})
    }
    
    response = lambda_handler(event)

    # Transforma a resposta do corpo
    response_body = json.loads(response["body"])
    assert response_body["message"] == "logout successful"


def test_lambda_handler_json_parsing(mock_auth_service, mock_resolver):
    """
    Testa se o lambda_handler consegue transformar uma string JSON em um objeto.
    
    Simula uma requisição que contém um corpo JSON e verifica se a resposta está correta.
    """
    event = {
        "body": '{"userId": "testuser", "password": "testpass"}',
        "httpMethod": "POST",
        "path": "/login"
    }

    # Configura o retorno esperado do método de login
    mock_auth_service.login.return_value = {"message": "login successful"}

    # Mock da resposta do resolver
    mock_resolver.resolve.return_value = {
        "statusCode": 200,
        "body": json.dumps({"message": "login successful"})
    }
    
    response = lambda_handler(event)

    # Transforma a resposta do corpo
    response_body = json.loads(response["body"])
    assert response_body["message"] == "login successful"
