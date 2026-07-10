from django.core import signing
from django.core.signing import Signer, TimestampSigner


def load_pickle_serializer(token):
    # ruleid: cra-python-django-signing-loads-untrusted
    return signing.loads(token, serializer=PickleSerializer)


def load_pickle_serializer_instance(token):
    # ruleid: cra-python-django-signing-loads-untrusted
    return signing.loads(token, serializer=PickleSerializer())


def unsign_object_pickle_signer(value):
    # ruleid: cra-python-django-signing-loads-untrusted
    return Signer().unsign_object(value, serializer=PickleSerializer)


def unsign_object_pickle_timestamp(value):
    # ruleid: cra-python-django-signing-loads-untrusted
    return TimestampSigner().unsign_object(value, serializer=PickleSerializer)


def load_default(token):
    # ok: cra-python-django-signing-loads-untrusted
    return signing.loads(token)


def load_json_serializer(token):
    # ok: cra-python-django-signing-loads-untrusted
    return signing.loads(token, serializer=JSONSerializer)


def unsign_object_default(value):
    signer = Signer()
    # ok: cra-python-django-signing-loads-untrusted
    return signer.unsign_object(value)


def unsign_plain_string(value):
    signer = Signer()
    # unsign() returns the signed string and does not deserialize objects.
    # ok: cra-python-django-signing-loads-untrusted
    return signer.unsign(value)


def dumps_pickle(payload):
    # ok: cra-python-django-signing-loads-untrusted
    return signing.dumps(payload, serializer=PickleSerializer)
