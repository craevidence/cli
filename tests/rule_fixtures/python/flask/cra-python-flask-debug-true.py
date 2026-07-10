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
