# ruleid: cra-python-django-allowed-hosts-wildcard
ALLOWED_HOSTS = ["*"]

# ruleid: cra-python-django-allowed-hosts-wildcard
ALLOWED_HOSTS = ["app.example.com", "*"]

# ok: cra-python-django-allowed-hosts-wildcard
ALLOWED_HOSTS = ["app.example.com", ".example.com"]
