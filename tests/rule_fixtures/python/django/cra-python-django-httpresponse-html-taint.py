from django.http import HttpResponse, HttpResponseBadRequest
from django.utils.html import escape


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
    return HttpResponse(f"<h1>Hello {escape(who)}</h1>")


def greet_static(request):
    # ok: cra-python-django-httpresponse-html-taint
    return HttpResponse("<h1>Hello world</h1>")


def greet_literal_placeholder(request):
    who = request.GET["name"]
    # ok: cra-python-django-httpresponse-html-taint
    return HttpResponse("<h1>Hello</h1>", status=200)
