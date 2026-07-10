import sqlalchemy
from sqlalchemy import text

ALLOWED = {"name", "email"}


def by_fstring(conn, name):
    # ruleid: cra-python-sqlalchemy-text-interpolation
    stmt = text(f"SELECT * FROM users WHERE name = '{name}'")
    return conn.execute(stmt).fetchall()


def by_format(conn, name):
    # ruleid: cra-python-sqlalchemy-text-interpolation
    stmt = text("SELECT * FROM users WHERE name = '{}'".format(name))
    return conn.execute(stmt).fetchall()


def by_percent(conn, name):
    # ruleid: cra-python-sqlalchemy-text-interpolation
    stmt = text("SELECT * FROM users WHERE name = '%s'" % name)
    return conn.execute(stmt).fetchall()


def by_concat(conn, name):
    # ruleid: cra-python-sqlalchemy-text-interpolation
    stmt = text("SELECT * FROM users WHERE name = '" + name)
    return conn.execute(stmt).fetchall()


def by_concat_left(conn, prefix):
    # ruleid: cra-python-sqlalchemy-text-interpolation
    stmt = text(prefix + " FROM users")
    return conn.execute(stmt).fetchall()


def by_qualified_fstring(conn, name):
    # ruleid: cra-python-sqlalchemy-text-interpolation
    stmt = sqlalchemy.text(f"SELECT * FROM users WHERE name = '{name}'")
    return conn.execute(stmt).fetchall()


def safe_bound(conn, name):
    # ok: cra-python-sqlalchemy-text-interpolation
    stmt = text("SELECT * FROM users WHERE name = :name")
    return conn.execute(stmt, {"name": name}).fetchall()


def safe_static_fstring(conn):
    # ok: cra-python-sqlalchemy-text-interpolation
    stmt = text(f"SELECT count(*) FROM users")
    return conn.execute(stmt).fetchall()


def safe_static_concat(conn):
    # ok: cra-python-sqlalchemy-text-interpolation
    stmt = text("SELECT * " + "FROM users")
    return conn.execute(stmt).fetchall()
