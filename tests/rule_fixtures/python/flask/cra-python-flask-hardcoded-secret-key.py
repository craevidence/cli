import os

from flask import Flask

app = Flask(__name__)


def config_subscript_literal():
    # ruleid: cra-python-flask-hardcoded-secret-key
    app.config['SECRET_KEY'] = 'dev-secret-123'


def secret_key_attribute_literal():
    # ruleid: cra-python-flask-hardcoded-secret-key
    app.secret_key = 'another-dev-secret'


def config_update_literal():
    # ruleid: cra-python-flask-hardcoded-secret-key
    app.config.update(SECRET_KEY='update-secret')


def config_bytes_literal():
    # ruleid: cra-python-flask-hardcoded-secret-key
    app.config['SECRET_KEY'] = b'\x00binary-secret'


def config_raw_literal():
    # ruleid: cra-python-flask-hardcoded-secret-key
    app.config['SECRET_KEY'] = r'raw-secret-value'


def config_from_environ():
    # ok: cra-python-flask-hardcoded-secret-key
    app.config['SECRET_KEY'] = os.environ['SECRET_KEY']


def config_from_getenv():
    # ok: cra-python-flask-hardcoded-secret-key
    app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")


def secret_key_from_variable():
    key = os.environ["SECRET_KEY"]
    # ok: cra-python-flask-hardcoded-secret-key
    app.secret_key = key


def empty_placeholder_default():
    # An empty or blank literal is the "must be set at runtime" placeholder,
    # not a committed secret.
    # ok: cra-python-flask-hardcoded-secret-key
    app.config['SECRET_KEY'] = ""
    # ok: cra-python-flask-hardcoded-secret-key
    app.config['SECRET_KEY'] = "   "


def config_dynamic_fstring():
    # An f-string is a format expression, not a committed literal secret.
    # ok: cra-python-flask-hardcoded-secret-key
    app.config['SECRET_KEY'] = f"{os.environ['SECRET_KEY']}"
