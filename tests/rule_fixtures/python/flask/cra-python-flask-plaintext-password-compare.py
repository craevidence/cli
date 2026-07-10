import hmac

from flask import request
from werkzeug.security import check_password_hash


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


def login_hashed(user):
    submitted = request.form["password"]
    # ok: cra-python-flask-plaintext-password-compare
    if check_password_hash(user.password_hash, submitted):
        return "ok"
    return "no", 401


def login_compare_digest(user):
    submitted = request.form["password"]
    # ok: cra-python-flask-plaintext-password-compare
    if hmac.compare_digest(submitted, user.password_hash):
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
