import os

import jwt
from jose import jwt as jose_jwt


def encode_positional_literal(payload):
    # ruleid: cra-python-jwt-hardcoded-secret
    return jwt.encode(payload, "super-secret-123", algorithm="HS256")


def encode_keyword_literal(payload):
    # ruleid: cra-python-jwt-hardcoded-secret
    return jwt.encode(payload, key="s3cr3tKeyValue", algorithm="HS256")


def decode_positional_literal(token):
    # ruleid: cra-python-jwt-hardcoded-secret
    return jwt.decode(token, "super-secret-123", algorithms=["HS256"])


def decode_jose_literal(token):
    # ruleid: cra-python-jwt-hardcoded-secret
    return jose_jwt.decode(token, "hardcodedSecret", algorithms=["HS256"])


def encode_from_env(payload):
    # ok: cra-python-jwt-hardcoded-secret
    return jwt.encode(payload, os.environ["JWT_SECRET"], algorithm="HS256")


def encode_from_variable(payload, signing_key):
    # ok: cra-python-jwt-hardcoded-secret
    return jwt.encode(payload, signing_key, algorithm="HS256")


def encode_from_settings(payload, settings):
    # ok: cra-python-jwt-hardcoded-secret
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def encode_short_placeholder(payload):
    # Below the length threshold, so it is not reported to keep noise down.
    # A short hardcoded key is still weak; the threshold is a tuning choice,
    # not a statement that this is safe.
    # ok: cra-python-jwt-hardcoded-secret
    return jwt.encode(payload, "abc", algorithm="HS256")
