from flask import request, redirect
import flask


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


def safe_literal():
    # ok: cra-python-flask-open-redirect
    return redirect("/dashboard")
