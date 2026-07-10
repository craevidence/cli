import sqlite3

from flask import request


def get_cursor():
    conn = sqlite3.connect(":memory:")
    return conn.cursor()


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


# Safe: sanitizer int() applied to tainted value before embedding in query
def ok_sql_sanitized_int(cur):
    raw = request.args.get("page")
    # int() is a declared sanitizer -- taint cleared
    page = int(raw)
    q = "SELECT * FROM items LIMIT 10 OFFSET " + str(page)
    # ok: cra-python-taint-sql-inject
    cur.execute(q)


# Safe: parameterized query -- tainted value passed as bind parameter
def ok_sql_parameterized(cur):
    uid = request.args.get("id")
    # ok: cra-python-taint-sql-inject
    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))
