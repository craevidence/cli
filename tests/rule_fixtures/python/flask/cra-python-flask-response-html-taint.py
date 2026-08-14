import base64
import html
import urllib.parse

import bleach
import flask
import markupsafe
from flask import Flask, jsonify, redirect, render_template, request

app = Flask(__name__)


def decorate(value):
    return "[" + value + "]"


def escape_for_html(value):
    return html.escape(value)


def sanitize(value):
    return value


@app.route("/greet-fstring")
def greet_fstring():
    name = request.args.get("name")
    # ruleid: cra-python-flask-response-html-taint
    return f"<h1>Hello {name}</h1>"


@app.route("/greet-accumulator", methods=["POST"])
def greet_accumulator():
    body = ""
    name = request.form.get("name")
    body += f"<p>Hello {name}</p>"
    # ruleid: cra-python-flask-response-html-taint
    return body


@app.route("/greet-concat")
def greet_concat():
    name = request.args["name"]
    # ruleid: cra-python-flask-response-html-taint
    return "<h1>Hello " + name + "</h1>"


@app.route("/greet-percent")
def greet_percent():
    name = request.cookies.get("name")
    # ruleid: cra-python-flask-response-html-taint
    return "<h1>Hello %s</h1>" % name


@app.route("/greet-format")
def greet_format():
    name = request.headers.get("X-Name")
    body = ""
    body += "<h1>Hello {0}</h1>".format(name)
    # ruleid: cra-python-flask-response-html-taint
    return body


@app.route("/greet-unquoted")
def greet_unquoted():
    name = urllib.parse.unquote_plus(request.cookies.get("name", ""))
    # ruleid: cra-python-flask-response-html-taint
    return f"<h1>Hello {name}</h1>"


@app.route("/greet-roundtrip")
def greet_roundtrip():
    name = request.args.get("name", "")
    encoded = base64.b64encode(name.encode("utf-8"))
    decoded = base64.b64decode(encoded).decode("utf-8")
    # ruleid: cra-python-flask-response-html-taint
    return f"<h1>Hello {decoded}</h1>"


@app.route("/greet-list")
def greet_list():
    names = request.args.getlist("name")
    first = names[0]
    # ruleid: cra-python-flask-response-html-taint
    return f"<h1>Hello {first}</h1>"


@app.route("/greet-helper")
def greet_helper():
    name = decorate(request.args.get("name", ""))
    # ruleid: cra-python-flask-response-html-taint
    return f"<h1>Hello {name}</h1>"


@app.post("/greet-post-shorthand")
def greet_post_shorthand():
    name = request.form.get("name")
    # ruleid: cra-python-flask-response-html-taint
    return f"<h1>Hello {name}</h1>"


@app.errorhandler(404)
def not_found(error):
    # ruleid: cra-python-flask-response-html-taint
    return f"<h1>No route for {request.full_path}</h1>", 404


@app.route("/greet-stdlib-escaped")
def greet_stdlib_escaped():
    name = request.args.get("name", "")
    # ok: cra-python-flask-response-html-taint
    return f"<h1>Hello {html.escape(name)}</h1>"


@app.route("/greet-assigned-stdlib-escaped")
def greet_assigned_stdlib_escaped():
    name = request.args.get("name", "")
    safe = html.escape(name)
    # ok: cra-python-flask-response-html-taint
    return f"<h1>Hello {safe}</h1>"


@app.route("/greet-markupsafe-escaped")
def greet_markupsafe_escaped():
    name = request.args.get("name", "")
    # ok: cra-python-flask-response-html-taint
    return f"<h1>Hello {markupsafe.escape(name)}</h1>"


@app.route("/greet-project-helper")
def greet_project_helper():
    name = request.args.get("name", "")
    body = f"<h1>Hello {escape_for_html(name)}</h1>"
    # ruleid: cra-python-flask-response-html-taint
    return body


@app.route("/greet-noop-sanitizer")
def greet_noop_sanitizer():
    name = request.args.get("name", "")
    body = f"<h1>Hello {sanitize(name)}</h1>"
    # ruleid: cra-python-flask-response-html-taint
    return body


@app.route("/greet-template")
def greet_template():
    name = request.args.get("name", "")
    # ok: cra-python-flask-response-html-taint
    return render_template("greet.html", name=name)


@app.route("/greet-json")
def greet_json():
    name = request.args.get("name", "")
    # ok: cra-python-flask-response-html-taint
    return jsonify(name=name)


@app.route("/greet-dict")
def greet_dict():
    # ok: cra-python-flask-response-html-taint
    return {"name": request.args.get("name", "")}


@app.route("/greet-list")
def greet_list():
    # ok: cra-python-flask-response-html-taint
    return [request.args.get("name", "")]


@app.route("/greet-redirect")
def greet_redirect():
    # A redirect does not build an HTML body, so the value is not an XSS sink.
    # The target is fixed here so the case does not introduce an open redirect.
    request.args.get("next", "/")
    # ok: cra-python-flask-response-html-taint
    return redirect("/home")


@app.route("/greet-redirect-tuple")
def greet_redirect_tuple():
    target = request.args.get("next", "/")
    # ok: cra-python-flask-response-html-taint
    return redirect(target), 302


@app.route("/greet-static")
def greet_static():
    # ok: cra-python-flask-response-html-taint
    return "<h1>Hello world</h1>"


def build_debug_line():
    name = request.args.get("name", "")
    # ok: cra-python-flask-response-html-taint
    return f"<h1>Hello {name}</h1>"


@app.route("/greet-bleach")
def greet_bleach():
    name = request.args.get("name", "")
    cleaned = bleach.clean(name)
    # ok: cra-python-flask-response-html-taint
    return f"<h1>Hello {cleaned}</h1>"


@app.route("/greet-flask-escape")
def greet_flask_escape():
    name = request.args.get("name", "")
    safe = flask.escape(name)
    # ok: cra-python-flask-response-html-taint
    return f"<h1>Hello {safe}</h1>"
