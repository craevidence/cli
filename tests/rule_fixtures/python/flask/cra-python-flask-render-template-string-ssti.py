from flask import request, render_template_string
import flask


def requested_template():
    return request.args.get("template")


def ssti_across_helper():
    template = requested_template()
    # ruleid: cra-python-flask-render-template-string-ssti
    return render_template_string(template)


def ssti_from_args():
    name = request.args.get("name")
    template = "<h1>Hello " + name + "</h1>"
    # ruleid: cra-python-flask-render-template-string-ssti
    return render_template_string(template)


def ssti_from_form():
    body = request.form.get("body")
    # ruleid: cra-python-flask-render-template-string-ssti
    return render_template_string("<p>" + body + "</p>")


def ssti_from_cookies_qualified():
    theme = request.cookies.get("theme")
    tpl = "<style>body{color:" + theme + "}</style>"
    # ruleid: cra-python-flask-render-template-string-ssti
    return flask.render_template_string(tpl)


def ssti_fully_qualified():
    # ruleid: cra-python-flask-render-template-string-ssti
    return flask.render_template_string(flask.request.args.get("template"))


def safe_context_variable():
    name = request.args.get("name")
    # ok: cra-python-flask-render-template-string-ssti
    return render_template_string("<h1>Hello {{ name }}</h1>", name=name)


def safe_constant_template():
    # ok: cra-python-flask-render-template-string-ssti
    return render_template_string("<h1>Static page</h1>")
