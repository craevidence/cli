import flask
import markupsafe
from flask import request
from markupsafe import Markup


def requested_bio():
    return request.form.get("bio")


def render_bio_across_helper():
    bio = requested_bio()
    # ruleid: cra-python-flask-markup-untrusted
    return Markup("<div>" + bio + "</div>")


def render_bio_concat():
    bio = request.form.get("bio")
    # ruleid: cra-python-flask-markup-untrusted
    return Markup("<div>" + bio + "</div>")


def render_bio_format():
    bio = request.args.get("bio")
    # ruleid: cra-python-flask-markup-untrusted
    return Markup("<div>{}</div>".format(bio))


def render_cookie():
    note = request.cookies.get("note")
    # ruleid: cra-python-flask-markup-untrusted
    return Markup("<span>" + note + "</span>")


def render_values_subscript():
    val = request.values["comment"]
    # ruleid: cra-python-flask-markup-untrusted
    return Markup("<p>" + val + "</p>")


def render_fully_qualified():
    # ruleid: cra-python-flask-markup-untrusted
    return flask.Markup(flask.request.args.get("bio"))


def render_bio_escaped():
    bio = request.form.get("bio")
    # ok: cra-python-flask-markup-untrusted
    return Markup("<div>" + markupsafe.escape(bio) + "</div>")


def render_bio_markup_escape():
    bio = request.form.get("bio")
    escaped = markupsafe.Markup.escape(bio)
    # ok: cra-python-flask-markup-untrusted
    return Markup("<div>" + escaped + "</div>")


def render_shadowed_escape():
    def escape(value):
        return value

    bio = request.form.get("bio")
    # ruleid: cra-python-flask-markup-untrusted
    return Markup("<div>" + escape(bio) + "</div>")


def render_constant():
    # ok: cra-python-flask-markup-untrusted
    return Markup("<div>static content</div>")


def render_internal(user):
    label = user.display_name
    # ok: cra-python-flask-markup-untrusted
    return Markup("<b>" + label + "</b>")
