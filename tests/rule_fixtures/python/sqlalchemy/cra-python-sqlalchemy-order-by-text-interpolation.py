from sqlalchemy import text

from models import User


def sort_fstring(session, sort):
    # ruleid: cra-python-sqlalchemy-order-by-text-interpolation
    return session.query(User).order_by(f"{sort} DESC").all()


def sort_concat(session, sort):
    # ruleid: cra-python-sqlalchemy-order-by-text-interpolation
    return session.query(User).order_by(sort + " DESC").all()


def sort_concat_right(session, direction):
    # ruleid: cra-python-sqlalchemy-order-by-text-interpolation
    return session.query(User).order_by("name " + direction).all()


def group_fstring(session, col):
    # ruleid: cra-python-sqlalchemy-order-by-text-interpolation
    return session.query(User).group_by(f"{col}").all()


def group_concat(session, col):
    # ruleid: cra-python-sqlalchemy-order-by-text-interpolation
    return session.query(User).group_by(col + ", id").all()


def sort_wrapped_text(session, sort):
    # ok: cra-python-sqlalchemy-order-by-text-interpolation
    return session.query(User).order_by(text(f"{sort} DESC")).all()


def sort_static_string(session):
    # ok: cra-python-sqlalchemy-order-by-text-interpolation
    return session.query(User).order_by("name" + " DESC").all()


def sort_mapped(session, sort):
    # ok: cra-python-sqlalchemy-order-by-text-interpolation
    cols = {"name": User.name, "created": User.created_at}
    col = cols.get(sort, User.id)
    return session.query(User).order_by(col.desc()).all()
