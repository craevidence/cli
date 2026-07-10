from flask import request, redirect, url_for
import flask


def open_redirect_from_args():
    target = request.args.get("next")
    # ruleid: cra-python-flask-open-redirect
    return redirect(target)


def open_redirect_from_referrer():
    back = request.referrer
    # ruleid: cra-python-flask-open-redirect
    return flask.redirect(back)


def safe_url_for():
    endpoint = request.args.get("next", "index")
    # ok: cra-python-flask-open-redirect
    return redirect(url_for(endpoint))


def safe_literal():
    # ok: cra-python-flask-open-redirect
    return redirect("/dashboard")
