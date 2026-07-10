from flask import Flask
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)


def disable_via_subscript():
    # ruleid: cra-python-flask-wtf-csrf-disabled
    app.config['WTF_CSRF_ENABLED'] = False


def disable_via_update():
    # ruleid: cra-python-flask-wtf-csrf-disabled
    app.config.update(WTF_CSRF_ENABLED=False)


def enabled_via_subscript():
    # ok: cra-python-flask-wtf-csrf-disabled
    app.config['WTF_CSRF_ENABLED'] = True


def enabled_via_variable(flag):
    # ok: cra-python-flask-wtf-csrf-disabled
    app.config['WTF_CSRF_ENABLED'] = flag


def protect_registered():
    # ok: cra-python-flask-wtf-csrf-disabled
    CSRFProtect(app)
