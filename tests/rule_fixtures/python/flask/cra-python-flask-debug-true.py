import os

from flask import Flask

app = Flask(__name__)


def run_literal_true():
    # ruleid: cra-python-flask-debug-true
    app.run(host="0.0.0.0", debug=True)


def config_subscript_true():
    # ruleid: cra-python-flask-debug-true
    app.config['DEBUG'] = True


def config_update_true():
    # ruleid: cra-python-flask-debug-true
    app.config.update(DEBUG=True)


def config_update_dict_true():
    # ruleid: cra-python-flask-debug-true
    app.config.update({"DEBUG": True})


def config_from_mapping_true():
    # ruleid: cra-python-flask-debug-true
    app.config.from_mapping(DEBUG=True)


def config_from_mapping_dict_true():
    # ruleid: cra-python-flask-debug-true
    app.config.from_mapping({"DEBUG": True})


def attribute_true():
    # ruleid: cra-python-flask-debug-true
    app.debug = True


def run_from_env():
    debug = os.environ.get("FLASK_DEBUG") == "1"
    # ok: cra-python-flask-debug-true
    app.run(host="127.0.0.1", debug=debug)


def config_from_env():
    # ok: cra-python-flask-debug-true
    app.config['DEBUG'] = os.environ.get("FLASK_DEBUG", "") == "1"


def run_default():
    # ok: cra-python-flask-debug-true
    app.run(host="127.0.0.1")


def run_false():
    # ok: cra-python-flask-debug-true
    app.run(host="127.0.0.1", debug=False)


def config_from_mapping_false():
    # ok: cra-python-flask-debug-true
    app.config.from_mapping(DEBUG=False)


def config_from_mapping_from_env():
    # ok: cra-python-flask-debug-true
    app.config.from_mapping(DEBUG=os.environ.get("FLASK_DEBUG") == "1")


class Config:
    """Base configuration loaded with app.config.from_object()."""

    # ruleid: cra-python-flask-debug-true
    DEBUG = True


class DevelopmentConfig(Config):
    # Debug mode is expected in a configuration class named for a development
    # environment, so this rule leaves it alone. The line carries no marker
    # because a bare DEBUG = True is also matched by the Django settings rule.
    DEBUG = True


class Runner:
    def start(self):
        # A local variable inside a method is not a Flask config value.
        DEBUG = True
        return DEBUG


class ProductionConfig(Config):
    # ok: cra-python-flask-debug-true
    DEBUG = False
