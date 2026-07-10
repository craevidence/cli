import os

from django.http import FileResponse
from django.utils._os import safe_join


def download_join(request):
    name = request.GET["f"]
    path = os.path.join("/srv/files", name)
    # ruleid: cra-python-django-file-path-traversal
    return FileResponse(open(path, "rb"))


def download_open(request):
    name = request.GET.get("f")
    # ruleid: cra-python-django-file-path-traversal
    return FileResponse(open(name, "rb"))


def download_post(request):
    name = request.POST["f"]
    path = os.path.join("/srv/files", name)
    # ruleid: cra-python-django-file-path-traversal
    return FileResponse(open(path, "rb"))


def compute_path_never_opened(request):
    name = request.GET["f"]
    # A path that is only computed and never opened is not a traversal sink.
    # ok: cra-python-django-file-path-traversal
    return os.path.join("/srv/files", name)


def download_basename(request):
    name = os.path.basename(request.GET["f"])
    path = os.path.join("/srv/files", name)
    # ok: cra-python-django-file-path-traversal
    return FileResponse(open(path, "rb"))


def download_safe_join(request):
    name = request.GET["f"]
    path = safe_join("/srv/files", name)
    # ok: cra-python-django-file-path-traversal
    return FileResponse(open(path, "rb"))


def download_static(request):
    path = os.path.join("/srv/files", "readme.txt")
    # ok: cra-python-django-file-path-traversal
    return FileResponse(open(path, "rb"))
