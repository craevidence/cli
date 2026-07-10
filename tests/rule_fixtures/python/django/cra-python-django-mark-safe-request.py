from django.http import HttpResponse
from django.utils.html import escape, format_html
from django.utils.safestring import mark_safe


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
    html = mark_safe("<div>" + escape(text) + "</div>")
    return HttpResponse(html)


def bio_format_html(request):
    text = request.GET["bio"]
    # ok: cra-python-django-mark-safe-request
    html = format_html("<div>{}</div>", text)
    return HttpResponse(html)


def bio_constant():
    # ok: cra-python-django-mark-safe-request
    html = mark_safe("<div>static content</div>")
    return HttpResponse(html)
