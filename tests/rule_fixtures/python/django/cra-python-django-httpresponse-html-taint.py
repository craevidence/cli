import html

from django.http import HttpResponse, HttpResponseBadRequest
import django.utils.html


def requested_name(request):
    return request.GET["name"]


def greet_across_helper(request):
    who = requested_name(request)
    # ruleid: cra-python-django-httpresponse-html-taint
    return HttpResponse(f"<h1>Hello {who}</h1>")


def greet_fstring(request):
    who = request.GET["name"]
    # ruleid: cra-python-django-httpresponse-html-taint
    return HttpResponse(f"<h1>Hello {who}</h1>")


def greet_concat(request):
    who = request.POST["name"]
    # ruleid: cra-python-django-httpresponse-html-taint
    return HttpResponse("<h1>Hello " + who + "</h1>")


def greet_percent(request):
    who = request.COOKIES.get("name")
    # ruleid: cra-python-django-httpresponse-html-taint
    return HttpResponse("<h1>Hello %s</h1>" % who)


def greet_badrequest(request):
    who = request.GET["name"]
    # ruleid: cra-python-django-httpresponse-html-taint
    return HttpResponseBadRequest("<p>{}</p>".format(who))


def greet_escaped(request):
    who = request.GET["name"]
    # ok: cra-python-django-httpresponse-html-taint
    return HttpResponse(f"<h1>Hello {django.utils.html.escape(who)}</h1>")


def greet_stdlib_escaped(request):
    who = request.GET["name"]
    # ok: cra-python-django-httpresponse-html-taint
    return HttpResponse(f"<h1>Hello {html.escape(who)}</h1>")


def greet_escapejs(request):
    who = request.GET["name"]
    # ok: cra-python-django-httpresponse-html-taint
    return HttpResponse(
        f"<script>const name = '{django.utils.html.escapejs(who)}';</script>"
    )


def greet_format_html(request):
    who = request.GET["name"]
    body = django.utils.html.format_html("<h1>Hello {}</h1>", who)
    # ok: cra-python-django-httpresponse-html-taint
    return HttpResponse(body)


def greet_shadowed_escape(request):
    def escape(value):
        return value

    who = request.GET["name"]
    # ruleid: cra-python-django-httpresponse-html-taint
    return HttpResponse(f"<h1>Hello {escape(who)}</h1>")


def greet_static(request):
    # ok: cra-python-django-httpresponse-html-taint
    return HttpResponse("<h1>Hello world</h1>")


def greet_literal_placeholder(request):
    who = request.GET["name"]
    # ok: cra-python-django-httpresponse-html-taint
    return HttpResponse("<h1>Hello</h1>", status=200)
