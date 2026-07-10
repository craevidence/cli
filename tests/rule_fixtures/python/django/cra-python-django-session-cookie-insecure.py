import os

# ruleid: cra-python-django-session-cookie-insecure
SESSION_COOKIE_SECURE = False

# ruleid: cra-python-django-session-cookie-insecure
CSRF_COOKIE_SECURE = False

# ok: cra-python-django-session-cookie-insecure
SESSION_COOKIE_SECURE = True

# ok: cra-python-django-session-cookie-insecure
CSRF_COOKIE_SECURE = True

# ok: cra-python-django-session-cookie-insecure
SESSION_COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "1") == "1"
