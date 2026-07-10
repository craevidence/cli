import jwt
from jose import jwt as jose_jwt

# Allowlisting 'none' is a dangerous configuration regardless of runtime: it is
# meant to accept unsigned tokens and is a bypass in libraries and versions that
# honor it. Current PyJWT rejects 'none' at decode time; the rule flags the
# configuration, not a live PyJWT exploit.


def decode_none_in_list(token, key):
    # ruleid: cra-python-jwt-decode-alg-none
    return jwt.decode(token, key, algorithms=["HS256", "none"])


def decode_none_only(token, key):
    # ruleid: cra-python-jwt-decode-alg-none
    return jwt.decode(token, key, algorithms=["none"])


def decode_none_uppercase(token, key):
    # ruleid: cra-python-jwt-decode-alg-none
    return jwt.decode(token, key, algorithms=["None"])


def decode_none_jose(token, key):
    # ruleid: cra-python-jwt-decode-alg-none
    return jose_jwt.decode(token, key, algorithms=["RS256", "none"])


def decode_none_bare_string(token, key):
    # ruleid: cra-python-jwt-decode-alg-none
    return jwt.decode(token, key, algorithms="none")


def decode_rs256_only(token, key):
    # ok: cra-python-jwt-decode-alg-none
    return jwt.decode(token, key, algorithms=["RS256"])


def decode_hs256_list(token, key):
    # ok: cra-python-jwt-decode-alg-none
    return jwt.decode(token, key, algorithms=["HS256", "HS384"])


def decode_bare_rs256(token, key):
    # ok: cra-python-jwt-decode-alg-none
    return jwt.decode(token, key, algorithms="RS256")
