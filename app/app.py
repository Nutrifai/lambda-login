from flask import Flask, request
from lambda_function import lambda_handler
import json

app = Flask(__name__)

def make_api_gateway_event():
    event = {
        "httpMethod": request.method,
        "path": request.path,
        "body": "",
        "headers": dict(request.headers),
        "queryStringParameters": request.args.to_dict(),
    }

    event["multiValueQueryStringParameters"] = {
        key: value.split(",")
        for key, value in event["queryStringParameters"].items()
    }

    try:
        event["body"] = request.get_json()
    except:
        pass

    return event

def make_lambda_url_event():
    event = {
        'rawPath': request.path,
        'rawQueryString': '',
        "headers": dict(request.headers),
        "requestContext": {
            'http': {
                'method': request.method,
                'path': request.path,
            },
            'stage': '$default',
        }
    }

    try:
        event["body"] = request.get_json()
    except:
        pass

    return event


@app.route("/<string:endpoint>", methods=['GET', 'POST', 'OPTIONS'])
@app.route("/<string:endpoint>/<string:pk>", methods=['GET', 'PUT', 'DELETE', 'OPTIONS'])
@app.route("/<string:endpoint>/<string:pk>/<string:sk>", methods=['GET', 'PUT', 'DELETE', 'OPTIONS'])
def handle_request(*args, **kwargs):
    response = lambda_handler(make_lambda_url_event())
    
    INSOMNIA_REQUEST = False

    if INSOMNIA_REQUEST and "body" in response and type(response["body"]) is str:
        response["body"] = json.loads(response["body"])

    body = response.pop("body", None)
    status_code = response.pop("statusCode", 200)
    headers = response.pop("headers", {})
    
    return body, status_code, headers


if __name__ == "__main__":
    app.run(debug=True, port=5002)