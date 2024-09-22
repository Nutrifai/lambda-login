import json
from aws_lambda_powertools.event_handler import APIGatewayHttpResolver, CORSConfig
from aws_lambda_powertools.event_handler.api_gateway import Router
from services.auth_service import AuthService
from utils.parse_cookies import parse_cookies

cors_config = CORSConfig(allow_credentials=True, expose_headers=["Set-Cookie"], allow_headers=["Set-Cookie"])
router = Router()

__auth_service: AuthService = None

def __setup_services():
    global __auth_service

    if __auth_service:
        return

    __auth_service = AuthService()


@router.post("/login")
def login():
    body = resolver.current_event.body
    user_id = body["userId"]
    password = body["password"]

    return __auth_service.login(user_id, password)

@router.post("/register")
def register():
    body = resolver.current_event.body
    return __auth_service.register_user(body)


@router.post("/logout")
def logout():
    cookies = resolver.current_event.get_header_value('Cookie')
    cookies_dict = parse_cookies(cookies)
    return __auth_service.logout(cookies_dict)
    

resolver = APIGatewayHttpResolver(cors=cors_config)
resolver.include_router(router=router, prefix="")

def lambda_handler(event, context = None):
    __setup_services()

    if "body" in event and type(event["body"]) is str:
        event["body"] = json.loads(event["body"])

    return resolver.resolve(event, context)