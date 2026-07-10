import os

# ruleid: cra-python-django-ssl-redirect-disabled
SECURE_SSL_REDIRECT = False

# ok: cra-python-django-ssl-redirect-disabled
SECURE_SSL_REDIRECT = True

# ok: cra-python-django-ssl-redirect-disabled
SECURE_SSL_REDIRECT = os.environ.get("SSL_REDIRECT", "1") == "1"
