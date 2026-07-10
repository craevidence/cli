import os

# ruleid: cra-python-django-settings-debug-true
DEBUG = True

ALLOWED_HOSTS = ["app.example.com"]

# ok: cra-python-django-settings-debug-true
DEBUG = os.environ.get("DJANGO_DEBUG", "") == "1"

# ok: cra-python-django-settings-debug-true
DEBUG = False
