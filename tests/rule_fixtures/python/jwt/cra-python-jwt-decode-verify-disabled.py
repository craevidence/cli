import jwt
from jose import jwt as jose_jwt


def read_claims_options_dict(token, key):
    # ruleid: cra-python-jwt-decode-verify-disabled
    claims = jwt.decode(token, key, algorithms=["HS256"], options={"verify_signature": False})
    return claims["sub"]


def read_claims_options_extra_keys(token, key):
    # ruleid: cra-python-jwt-decode-verify-disabled
    claims = jwt.decode(token, key, options={"verify_aud": False, "verify_signature": False})
    return claims["sub"]


def read_claims_jose_options(token, key):
    # ruleid: cra-python-jwt-decode-verify-disabled
    claims = jose_jwt.decode(token, key, options={"verify_signature": False})
    return claims["sub"]


def read_claims_verified(token, key):
    # ok: cra-python-jwt-decode-verify-disabled
    claims = jwt.decode(token, key, algorithms=["HS256"])
    return claims["sub"]


def peek_header(token):
    # ok: cra-python-jwt-decode-verify-disabled
    header = jwt.get_unverified_header(token)
    return header["kid"]


def read_claims_options_present_but_enabled(token, key):
    # ok: cra-python-jwt-decode-verify-disabled
    claims = jwt.decode(token, key, algorithms=["HS256"], options={"verify_aud": False})
    return claims["sub"]
