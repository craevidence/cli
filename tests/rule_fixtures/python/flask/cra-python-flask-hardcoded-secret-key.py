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


def config_update_dict_literal():
    # ruleid: cra-python-flask-hardcoded-secret-key
    app.config.update({"SECRET_KEY": "update-dict-secret"})


def config_from_mapping_literal():
    # ruleid: cra-python-flask-hardcoded-secret-key
    app.config.from_mapping(SECRET_KEY="mapping-secret")


def config_from_mapping_dict_literal():
    # ruleid: cra-python-flask-hardcoded-secret-key
    app.config.from_mapping({"SECRET_KEY": "mapping-dict-secret"})


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


def config_from_mapping_environ():
    # ok: cra-python-flask-hardcoded-secret-key
    app.config.from_mapping(SECRET_KEY=os.environ["SECRET_KEY"])


def config_from_mapping_dict_environ():
    # ok: cra-python-flask-hardcoded-secret-key
    app.config.from_mapping({"SECRET_KEY": os.environ.get("SECRET_KEY")})


class Config:
    """Base configuration loaded with app.config.from_object()."""

    # ruleid: cra-python-flask-hardcoded-secret-key
    SECRET_KEY = "class-config-secret"


class TestingConfig(Config):
    # A throwaway key in a configuration class named for tests is deliberate,
    # so this rule leaves it alone. The line carries no marker because a bare
    # SECRET_KEY assignment is also matched by the Django settings rule.
    SECRET_KEY = "testing-only"


class Runner:
    def start(self):
        # A local variable inside a method is not a Flask config value.
        SECRET_KEY = "local-only"
        return SECRET_KEY


class ProductionConfig(Config):
    # ok: cra-python-flask-hardcoded-secret-key
    SECRET_KEY = os.environ["SECRET_KEY"]
