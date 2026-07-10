from django.shortcuts import redirect, resolve_url
from django.http import (
    HttpResponseRedirect,
    HttpResponsePermanentRedirect,
)
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme


def go_shortcut(request):
    nxt = request.GET.get("next")
    # ruleid: cra-python-django-open-redirect
    return redirect(nxt)


def go_subscript(request):
    nxt = request.GET["next"]
    # ruleid: cra-python-django-open-redirect
    return HttpResponseRedirect(nxt)


def go_permanent(request):
    nxt = request.POST.get("next")
    # ruleid: cra-python-django-open-redirect
    return HttpResponsePermanentRedirect(nxt)


def go_header(request):
    back = request.META.get("HTTP_REFERER")
    # ruleid: cra-python-django-open-redirect
    return redirect(back)


def go_validated(request):
    nxt = request.GET.get("next")
    if url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()}):
        # ok: cra-python-django-open-redirect
        return redirect(nxt)
    return redirect("/")


def go_reverse(request):
    name = request.GET.get("view")
    # ok: cra-python-django-open-redirect
    return redirect(reverse(name))


def go_resolve(request):
    name = request.GET.get("view")
    # resolve_url returns a URL string unchanged, so a request-supplied
    # absolute URL still redirects off-site.
    # ruleid: cra-python-django-open-redirect
    return HttpResponseRedirect(resolve_url(name))


def go_static(request):
    # ok: cra-python-django-open-redirect
    return redirect("/dashboard/")
