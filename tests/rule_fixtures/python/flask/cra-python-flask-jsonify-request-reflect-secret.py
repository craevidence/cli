import os

import flask
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/h1")
def reflect_headers():
    # ruleid: cra-python-flask-jsonify-request-reflect-secret
    return jsonify(request.headers)


@app.route("/h1q")
def reflect_headers_qualified():
    # ruleid: cra-python-flask-jsonify-request-reflect-secret
    return flask.jsonify(request.headers)


@app.route("/h2")
def reflect_headers_dict():
    # ruleid: cra-python-flask-jsonify-request-reflect-secret
    return jsonify(dict(request.headers))


@app.route("/h3")
def reflect_headers_spread():
    # ruleid: cra-python-flask-jsonify-request-reflect-secret
    return jsonify(**request.headers)


@app.route("/c1")
def reflect_cookies():
    # ruleid: cra-python-flask-jsonify-request-reflect-secret
    return jsonify(request.cookies)


@app.route("/c2")
def reflect_cookies_dict():
    # ruleid: cra-python-flask-jsonify-request-reflect-secret
    return jsonify(dict(request.cookies))


@app.route("/e1")
def reflect_environ():
    # ruleid: cra-python-flask-jsonify-request-reflect-secret
    return jsonify(request.environ)


@app.route("/e2")
def reflect_os_environ():
    # ruleid: cra-python-flask-jsonify-request-reflect-secret
    return jsonify(os.environ)


@app.route("/e3")
def reflect_os_environ_dict():
    # ruleid: cra-python-flask-jsonify-request-reflect-secret
    return jsonify(dict(os.environ))


@app.route("/e4")
def reflect_os_environ_spread():
    # ruleid: cra-python-flask-jsonify-request-reflect-secret
    return jsonify(**os.environ)


@app.route("/cfg1")
def reflect_config():
    # ruleid: cra-python-flask-jsonify-request-reflect-secret
    return jsonify(app.config)


@app.route("/cfg2")
def reflect_config_dict():
    # ruleid: cra-python-flask-jsonify-request-reflect-secret
    return jsonify(dict(app.config))


@app.route("/whoami")
def whoami():
    # ok: cra-python-flask-jsonify-request-reflect-secret
    return jsonify(user=request.headers.get("X-User"))


@app.route("/one-cookie")
def one_cookie():
    # ok: cra-python-flask-jsonify-request-reflect-secret
    return jsonify(session=request.cookies["session"])


@app.route("/static")
def static_payload():
    # ok: cra-python-flask-jsonify-request-reflect-secret
    return jsonify(status="ok")
