import os

from flask import Flask, make_response

app = Flask(__name__)


def config_subscript_false():
    # ruleid: cra-python-flask-session-cookie-insecure-false
    app.config['SESSION_COOKIE_SECURE'] = False


def config_update_false():
    # ruleid: cra-python-flask-session-cookie-insecure-false
    app.config.update(SESSION_COOKIE_SECURE=False)


def config_subscript_true():
    # ok: cra-python-flask-session-cookie-insecure-false
    app.config['SESSION_COOKIE_SECURE'] = True


def config_from_env():
    # ok: cra-python-flask-session-cookie-insecure-false
    app.config['SESSION_COOKIE_SECURE'] = os.environ.get("COOKIE_SECURE") != "0"


def response_cookie_secure_false(value):
    response = make_response("body")
    # ruleid: cra-python-flask-session-cookie-insecure-false
    response.set_cookie("session_token", value, secure=False, httponly=True)
    return response


def response_cookie_secure_false_multiline(value):
    response = make_response("body")
    response.set_cookie(
        "session_token",
        value,
        max_age=180,
        # ruleid: cra-python-flask-session-cookie-insecure-false
        secure=False,
        httponly=True,
    )
    return response


def response_cookie_keyword_form(value):
    response = make_response("body")
    # ruleid: cra-python-flask-session-cookie-insecure-false
    response.set_cookie(key="session_token", value=value, secure=False)
    return response


def response_cookie_secure_true(value):
    response = make_response("body")
    # ok: cra-python-flask-session-cookie-insecure-false
    response.set_cookie("session_token", value, secure=True, httponly=True)
    return response


def response_cookie_secure_from_config(value):
    response = make_response("body")
    # ok: cra-python-flask-session-cookie-insecure-false
    response.set_cookie("session_token", value, secure=app.config["COOKIE_SECURE"])
    return response


def response_cookie_secure_omitted(value):
    response = make_response("body")
    # ok: cra-python-flask-session-cookie-insecure-false
    response.set_cookie("session_token", value, httponly=True)
    return response
