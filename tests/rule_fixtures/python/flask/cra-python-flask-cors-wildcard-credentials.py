import re

from flask import Flask
from flask_cors import CORS, cross_origin

app = Flask(__name__)


def cors_wildcard_string():
    # ruleid: cra-python-flask-cors-wildcard-credentials
    CORS(app, origins="*", supports_credentials=True)


def cors_wildcard_list():
    # ruleid: cra-python-flask-cors-wildcard-credentials
    CORS(app, origins=["*"], supports_credentials=True)


def cors_wildcard_regex_string():
    # ruleid: cra-python-flask-cors-wildcard-credentials
    CORS(app, origins=".*", supports_credentials=True)


def cors_wildcard_regex_compiled():
    # ruleid: cra-python-flask-cors-wildcard-credentials
    CORS(app, origins=re.compile(".*"), supports_credentials=True)


@app.route("/data")
# ruleid: cra-python-flask-cors-wildcard-credentials
@cross_origin(origins="*", supports_credentials=True)
def data():
    return "ok"


def cors_explicit_allowlist_with_credentials():
    # ok: cra-python-flask-cors-wildcard-credentials
    CORS(app, origins=["https://app.example.com"], supports_credentials=True)


def cors_wildcard_without_credentials():
    # ok: cra-python-flask-cors-wildcard-credentials
    CORS(app, origins="*")


def cors_variable_origins_with_credentials(allowed):
    # ok: cra-python-flask-cors-wildcard-credentials
    CORS(app, origins=allowed, supports_credentials=True)
