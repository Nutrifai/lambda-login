import json
from aws_lambda_powertools.event_handler import APIGatewayHttpResolver, CORSConfig
from aws_lambda_powertools.event_handler.api_gateway import Router
from services.auth_service import AuthService
from utils.parse_cookies import parse_cookies

"""
Configure Cross-Origin Resource Sharing (CORS) settings for the `APIGatewayHttpResolver`. 

- `allow_credentials=True`: Allows cookies and HTTP authentication information to be included in requests.
- `expose_headers=["Set-Cookie"]`: Specifies which headers can be exposed as part of the response.
- `allow_headers=["Set-Cookie"]`: Specifies which headers can be used in the actual request.

This configuration is essential for handling CORS in a secure manner, especially when dealing with cookies for authentication.
"""
cors_config = CORSConfig(allow_credentials=True, expose_headers=["Set-Cookie"], allow_headers=["Set-Cookie"])

# Initialize the router for handling API Gateway events
router = Router()

# Global variable to hold the AuthService instance
__auth_service: AuthService = None

def __setup_services():
    """
    Initialize the AuthService instance if it hasn't been initialized yet.
    """
    global __auth_service

    if __auth_service:
        return

    __auth_service = AuthService()


@router.post("/login")
def login():
    """
    Handle the login request.

    Expects a JSON body with 'userId' and 'password' fields.

    Example: {"userId": "user", "password": "12345678"}

    Returns:
        Response from AuthService.login method.
    """
    body = resolver.current_event.body
    user_id = body["userId"]
    password = body["password"]

    return __auth_service.login(user_id, password)

@router.post("/register")
def register():
    """
    Handle the user registration request.

    Expects a JSON body with 'userId', 'email' and 'password' fields.

    Example: {"userId": "user", "email": "user@gmail", "password": "12345678"}

    Returns:
        Response from AuthService.register_user method.
    """
    body = resolver.current_event.body
    return __auth_service.register_user(body)


@router.post("/logout")
def logout():
    """
    Handle the logout request.

    Expects a 'Cookie' header with session information.

    Example: Cookie:sessionId=1b9ba95110f586136b4a77592a9e9e40

    Returns:
        Response from AuthService.logout method.
    """
    cookies = resolver.current_event.get_header_value('Cookie')
    cookies_dict = parse_cookies(cookies)
    return __auth_service.logout(cookies_dict)
    

# APIGatewayHttpResolver` is a class from the `aws_lambda_powertools` library, designed to simplify the handling of AWS API Gateway events in AWS Lambda functions
resolver = APIGatewayHttpResolver(cors=cors_config)
resolver.include_router(router=router, prefix="")

def lambda_handler(event, context = None):
    """
    AWS Lambda handler function.

    Args:
        event (dict): The event dictionary containing request data.
        context (object, optional): The context object containing runtime information.

    Returns:
        dict: The response dictionary to be returned to API Gateway.
    """
    __setup_services()

    if "body" in event and type(event["body"]) is str:
        event["body"] = json.loads(event["body"])

    response = resolver.resolve(event, context)

    # if "body" in response and type(response["body"]) is not str:
    #     response["body"] = json.dumps(response["body"], ensure_ascii=False)

    return response
