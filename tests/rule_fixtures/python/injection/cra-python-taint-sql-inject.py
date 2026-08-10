import sqlite3

import flask
from flask import request


def get_cursor():
    conn = sqlite3.connect(":memory:")
    return conn.cursor()


def requested_user_id():
    return request.args.get("id")


def bad_sql_across_helper(cur):
    user_id = requested_user_id()
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    # ruleid: cra-python-taint-sql-inject
    cur.execute(query)


# Bad: request.args tainted -> execute (sink, query arg)
def bad_sql_from_args(cur):
    uid = request.args.get("id")
    query = "SELECT * FROM users WHERE id = '" + uid + "'"
    # ruleid: cra-python-taint-sql-inject
    cur.execute(query)


# Bad: request.form tainted -> execute (sink)
def bad_sql_from_form(cur):
    name = request.form.get("name")
    q = "SELECT * FROM users WHERE name = '" + name + "'"
    # ruleid: cra-python-taint-sql-inject
    cur.execute(q)


# Bad: request.json tainted -> execute (sink)
def bad_sql_from_json(cur):
    payload = request.json
    q = "DELETE FROM tokens WHERE value = '" + str(payload) + "'"
    # ruleid: cra-python-taint-sql-inject
    cur.execute(q)


# Bad: request.cookies tainted -> execute (sink)
def bad_sql_from_cookie(cur):
    token = request.cookies.get("session")
    q = "SELECT * FROM sessions WHERE token = '" + token + "'"
    # ruleid: cra-python-taint-sql-inject
    cur.execute(q)


# Bad: qualified flask.request source -> execute (sink)
def bad_sql_from_qualified_request(cur):
    uid = flask.request.args.get("id")
    query = "SELECT * FROM users WHERE id = '" + uid + "'"
    # ruleid: cra-python-taint-sql-inject
    cur.execute(query)


# Unsafe: a local callable named int is not the Python numeric conversion.
def bad_sql_shadowed_int(cur, int):
    raw = request.args.get("page")
    page = int(raw)
    q = "SELECT * FROM items LIMIT 10 OFFSET " + str(page)
    # ruleid: cra-python-taint-sql-inject
    cur.execute(q)


# Safe: parameterized query -- tainted value passed as bind parameter
def ok_sql_parameterized(cur):
    uid = request.args.get("id")
    # ok: cra-python-taint-sql-inject
    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))
