import jwt


def decode_positional_key_no_algorithms(token, public_key):
    # ruleid: cra-python-jwt-decode-missing-algorithms
    return jwt.decode(token, public_key)


def decode_keyword_key_no_algorithms(token, public_key):
    # ruleid: cra-python-jwt-decode-missing-algorithms
    return jwt.decode(token, key=public_key)


def decode_unrelated_bare_function(blob, codec):
    # A bare decode() from another library is not a PyJWT call.
    # ok: cra-python-jwt-decode-missing-algorithms
    return decode(blob, codec)


def decode_with_algorithms(token, public_key):
    # ok: cra-python-jwt-decode-missing-algorithms
    return jwt.decode(token, public_key, algorithms=["RS256"])


def decode_keyword_with_algorithms(token, public_key):
    # ok: cra-python-jwt-decode-missing-algorithms
    return jwt.decode(token, key=public_key, algorithms=["HS256"])


def decode_verify_disabled(token, public_key):
    # ok: cra-python-jwt-decode-missing-algorithms
    return jwt.decode(token, public_key, options={"verify_signature": False})


def decode_unverified_peek(token):
    # ok: cra-python-jwt-decode-missing-algorithms
    return jwt.decode(token, options={"verify_signature": False})
