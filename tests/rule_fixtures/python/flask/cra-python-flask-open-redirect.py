from flask import request, redirect
from urllib.parse import urlparse
import flask
import urllib.parse


def requested_redirect():
    return request.args.get("next")


def open_redirect_across_helper():
    target = requested_redirect()
    # ruleid: cra-python-flask-open-redirect
    return redirect(target)


def open_redirect_from_args():
    target = request.args.get("next")
    # ruleid: cra-python-flask-open-redirect
    return redirect(target)


def open_redirect_from_referrer():
    back = request.referrer
    # ruleid: cra-python-flask-open-redirect
    return flask.redirect(back)


def open_redirect_fully_qualified():
    # ruleid: cra-python-flask-open-redirect
    return flask.redirect(flask.request.args.get("next"))


def safe_url_for():
    endpoint = request.args.get("next", "index")
    # ok: cra-python-flask-open-redirect
    return redirect(flask.url_for(endpoint))


def unsafe_shadowed_url_for():
    def url_for(value):
        return value

    endpoint = request.args.get("next", "index")
    # ruleid: cra-python-flask-open-redirect
    return redirect(url_for(endpoint))


def open_redirect_from_cookie():
    target = request.cookies.get("next")
    # ruleid: cra-python-flask-open-redirect
    return flask.redirect(target)


def open_redirect_from_query_string():
    target = request.query_string.decode("utf-8")
    # ruleid: cra-python-flask-open-redirect
    return flask.redirect(target)


def safe_allowlisted_host():
    target = request.args.get("next")
    parsed = urllib.parse.urlparse(target)
    if parsed.netloc not in ("example.com", "www.example.com"):
        return "rejected"
    # ok: cra-python-flask-open-redirect
    return flask.redirect(target)


def safe_allowlisted_hostname_and_scheme():
    target = request.args.get("next")
    parsed = urlparse(target)
    if parsed.hostname not in ("example.com",) or parsed.scheme != "https":
        return "rejected"
    # ok: cra-python-flask-open-redirect
    return flask.redirect(target)


def open_redirect_allowlist_checks_other_value():
    target = request.args.get("next")
    parsed = urllib.parse.urlparse(request.args.get("origin"))
    if parsed.netloc not in ("example.com",):
        return "rejected"
    # ruleid: cra-python-flask-open-redirect
    return flask.redirect(target)


def safe_literal():
    # ok: cra-python-flask-open-redirect
    return redirect("/dashboard")
