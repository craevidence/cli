import os

from decouple import config

# ruleid: cra-python-django-hardcoded-secret-key
SECRET_KEY = "django-insecure-9v!x2h_abc123realkeyvalue"

# ruleid: cra-python-django-hardcoded-secret-key
SECRET_KEY_FALLBACKS = ["old-insecure-key-abc123"]

# ruleid: cra-python-django-hardcoded-secret-key
SECRET_KEY = r"raw-insecure-secret-key-abc123"

# An f-string is a format expression, not a committed literal secret.
# ok: cra-python-django-hardcoded-secret-key
SECRET_KEY = f"{os.environ['DJANGO_SECRET_KEY']}"

# ok: cra-python-django-hardcoded-secret-key
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]

# ok: cra-python-django-hardcoded-secret-key
SECRET_KEY = config("DJANGO_SECRET_KEY")

# An empty or blank literal is the "must be set at runtime" placeholder default,
# not a committed secret.
# ok: cra-python-django-hardcoded-secret-key
SECRET_KEY = ""
