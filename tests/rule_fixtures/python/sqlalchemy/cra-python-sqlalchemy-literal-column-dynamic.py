import sqlalchemy
from sqlalchemy import literal_column, select


def order_fstring(conn, users, col):
    # ruleid: cra-python-sqlalchemy-literal-column-dynamic
    stmt = select(literal_column(f"{col}")).select_from(users)
    return conn.execute(stmt).all()


def order_format(conn, users, col):
    # ruleid: cra-python-sqlalchemy-literal-column-dynamic
    stmt = select(literal_column("{}".format(col))).select_from(users)
    return conn.execute(stmt).all()


def order_percent(conn, users, col):
    # ruleid: cra-python-sqlalchemy-literal-column-dynamic
    stmt = select(literal_column("%s" % col)).select_from(users)
    return conn.execute(stmt).all()


def order_concat(conn, users, col):
    # ruleid: cra-python-sqlalchemy-literal-column-dynamic
    stmt = select(literal_column(col + " DESC")).select_from(users)
    return conn.execute(stmt).all()


def order_concat_right(conn, users, suffix):
    # ruleid: cra-python-sqlalchemy-literal-column-dynamic
    stmt = select(literal_column("name" + suffix)).select_from(users)
    return conn.execute(stmt).all()


def order_qualified(conn, users, col):
    # ruleid: cra-python-sqlalchemy-literal-column-dynamic
    stmt = select(sqlalchemy.literal_column(f"{col} ASC")).select_from(users)
    return conn.execute(stmt).all()


def safe_mapped(conn, users, col):
    # ok: cra-python-sqlalchemy-literal-column-dynamic
    column = users.c[col]
    return conn.execute(select(column)).all()


def safe_static_literal(conn, users):
    # ok: cra-python-sqlalchemy-literal-column-dynamic
    return conn.execute(select(literal_column("now()"))).all()


def safe_static_concat(conn, users):
    # ok: cra-python-sqlalchemy-literal-column-dynamic
    return conn.execute(select(literal_column("id" + " DESC"))).all()
