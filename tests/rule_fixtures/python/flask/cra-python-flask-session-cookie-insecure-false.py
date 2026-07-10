import os

from flask import Flask

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
