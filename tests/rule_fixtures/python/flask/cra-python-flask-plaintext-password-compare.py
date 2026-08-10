import hmac

import bcrypt
import flask
from flask import request
import werkzeug.security


def submitted_password():
    return request.form["password"]


def login_across_helper(user):
    submitted = submitted_password()
    # ruleid: cra-python-flask-plaintext-password-compare
    if submitted == user.password:
        return "ok"
    return "no", 401


def login_subscript(user):
    submitted = request.form["password"]
    # ruleid: cra-python-flask-plaintext-password-compare
    if submitted == user.password:
        return "ok"
    return "no", 401


def login_get(user):
    submitted = request.form.get("passwd")
    # ruleid: cra-python-flask-plaintext-password-compare
    if user.password == submitted:
        return "ok"
    return "no", 401


def login_not_equal(row):
    submitted = request.values["pwd"]
    # ruleid: cra-python-flask-plaintext-password-compare
    if submitted != row["password"]:
        return "no", 401
    return "ok"


def login_json(user):
    submitted = request.json["password"]
    # ruleid: cra-python-flask-plaintext-password-compare
    if submitted == user.password:
        return "ok"
    return "no", 401


def login_fully_qualified(user):
    submitted = flask.request.form["password"]
    # ruleid: cra-python-flask-plaintext-password-compare
    if submitted == user.password:
        return "ok"
    return "no", 401


def login_hashed(user):
    submitted = request.form["password"]
    # ok: cra-python-flask-plaintext-password-compare
    if werkzeug.security.check_password_hash(user.password_hash, submitted):
        return "ok"
    return "no", 401


def login_shadowed_hash_helper(user):
    def check_password_hash(stored, submitted):
        return stored == submitted

    submitted = request.form["password"]
    candidate = check_password_hash(user.password_hash, submitted)
    # ruleid: cra-python-flask-plaintext-password-compare
    if submitted == user.password:
        return candidate
    return "no", 401


def login_compare_digest(user):
    submitted = request.form["password"]
    # ok: cra-python-flask-plaintext-password-compare
    if hmac.compare_digest(submitted, user.password_hash):
        return "ok"
    return "no", 401


def login_bcrypt(user):
    submitted = request.form["password"]
    # ok: cra-python-flask-plaintext-password-compare
    if bcrypt.checkpw(submitted.encode(), user.password_hash):
        return "ok"
    return "no", 401


def check_token(user):
    submitted = request.form["token"]
    # ok: cra-python-flask-plaintext-password-compare
    if submitted == user.api_token:
        return "ok"
    return "no", 401


def signup_confirmation():
    password = request.form["password"]
    confirmation = request.form["password_confirmation"]
    # Comparing two request-supplied values is a confirmation check, not a
    # credential verification against a stored value.
    # ok: cra-python-flask-plaintext-password-compare
    if password != confirmation:
        return "mismatch", 400
    return "ok"
