from flask import request, send_file, send_from_directory
import flask
from werkzeug.utils import safe_join, secure_filename


def traversal_from_args():
    name = request.args.get("file")
    # ruleid: cra-python-flask-send-file-path-traversal
    return send_file("/var/data/" + name)


def traversal_from_view_args():
    name = request.view_args["file"]
    path = "/var/data/" + name
    # ruleid: cra-python-flask-send-file-path-traversal
    return flask.send_file(path)


def safe_send_from_directory():
    name = request.args.get("file")
    # ok: cra-python-flask-send-file-path-traversal
    return send_from_directory("/var/data", name)


def safe_safe_join():
    name = request.args.get("file")
    path = safe_join("/var/data", name)
    # ok: cra-python-flask-send-file-path-traversal
    return send_file(path)


def safe_secure_filename():
    name = secure_filename(request.args.get("file"))
    # ok: cra-python-flask-send-file-path-traversal
    return send_file("/var/data/" + name)
