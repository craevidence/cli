import html

import bleach
import django.utils.html
import nh3
from django.http import HttpResponse
from django.utils.html import escape as django_escape
from django.utils.safestring import mark_safe


def requested_bio(request):
    return request.GET["bio"]


def bio_across_helper(request):
    text = requested_bio(request)
    # ruleid: cra-python-django-mark-safe-request
    return mark_safe("<div>" + text + "</div>")


def bio_get(request):
    text = request.GET["bio"]
    # ruleid: cra-python-django-mark-safe-request
    html = mark_safe(f"<div>{text}</div>")
    return HttpResponse(html)


def bio_post(request):
    text = request.POST["bio"]
    # ruleid: cra-python-django-mark-safe-request
    html = mark_safe("<div>" + text + "</div>")
    return HttpResponse(html)


def bio_cookie(request):
    text = request.COOKIES.get("bio")
    # ruleid: cra-python-django-mark-safe-request
    html = mark_safe("<div>%s</div>" % text)
    return HttpResponse(html)


def bio_cleaned(form):
    text = form.cleaned_data
    # ruleid: cra-python-django-mark-safe-request
    return mark_safe("<div>{}</div>".format(text))


def bio_escaped(request):
    text = request.GET["bio"]
    # ok: cra-python-django-mark-safe-request
    html = mark_safe("<div>" + django.utils.html.escape(text) + "</div>")
    return HttpResponse(html)


def bio_format_html(request):
    text = request.GET["bio"]
    # ok: cra-python-django-mark-safe-request
    html = django.utils.html.format_html("<div>{}</div>", text)
    return HttpResponse(html)


def bio_stdlib_escape(request):
    text = request.GET["bio"]
    # ok: cra-python-django-mark-safe-request
    return mark_safe("<div>" + html.escape(text) + "</div>")


def bio_conditional_escape(request):
    text = request.GET["bio"]
    # ok: cra-python-django-mark-safe-request
    return mark_safe(
        "<div>" + django.utils.html.conditional_escape(text) + "</div>"
    )


def bio_bleach_clean(request):
    text = request.GET["bio"]
    # ok: cra-python-django-mark-safe-request
    return mark_safe("<div>" + bleach.clean(text) + "</div>")


def bio_nh3_clean(request):
    text = request.GET["bio"]
    # ok: cra-python-django-mark-safe-request
    return mark_safe("<div>" + nh3.clean(text) + "</div>")


def bio_import_alias(request):
    text = request.GET["bio"]
    # ok: cra-python-django-mark-safe-request
    return mark_safe("<div>" + django_escape(text) + "</div>")


def bio_shadowed_escape(request):
    def escape(value):
        return value

    text = request.GET["bio"]
    # ruleid: cra-python-django-mark-safe-request
    return mark_safe("<div>" + escape(text) + "</div>")


def bio_constant():
    # ok: cra-python-django-mark-safe-request
    html = mark_safe("<div>static content</div>")
    return HttpResponse(html)
