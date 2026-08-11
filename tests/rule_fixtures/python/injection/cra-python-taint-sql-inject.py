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


# Bad: the value is read with subscript access rather than get()
def bad_subscript_args_to_query(cursor):
    identifier = request.args["id"]
    # ruleid: cra-python-taint-sql-inject
    cursor.execute("SELECT * FROM items WHERE id = " + identifier)


# Bad: the query text itself is tainted even though a value is bound separately
def bad_sql_tainted_query_with_bind_param(cur):
    column = request.args.get("sort")
    # ruleid: cra-python-taint-sql-inject
    cur.execute("SELECT " + column + " FROM users WHERE id = ?", (1,))


# Bad: executemany builds its query text from a request value
def bad_sql_executemany(cur):
    table = request.args.get("table")
    # ruleid: cra-python-taint-sql-inject
    cur.executemany("INSERT INTO " + table + " (a) VALUES (?)", [(1,), (2,)])


# Safe: executemany with a constant query and tainted values bound as parameters
def ok_sql_executemany_parameterized(cur):
    name = request.form.get("name")
    # ok: cra-python-taint-sql-inject
    cur.executemany("INSERT INTO users (name) VALUES (?)", [(name,)])


# Bad: executescript runs the whole string as SQL
def bad_sql_executescript(cur):
    script = request.form.get("script")
    # ruleid: cra-python-taint-sql-inject
    cur.executescript(script)


# Bad: a Django raw queryset with the value embedded in the query text
def bad_sql_django_raw(person_model):
    name = request.args.get("name")
    # ruleid: cra-python-taint-sql-inject
    return person_model.objects.raw("SELECT * FROM person WHERE name = '" + name + "'")


# Safe: a Django raw queryset with the value passed as a parameter
def ok_sql_django_raw_parameterized(person_model):
    name = request.args.get("name")
    # ok: cra-python-taint-sql-inject
    return person_model.objects.raw("SELECT * FROM person WHERE name = %s", [name])


# Bad: a multi-value accessor is a source
def bad_sql_from_getlist(cur):
    ids = request.args.getlist("id")
    # ruleid: cra-python-taint-sql-inject
    cur.execute("SELECT * FROM users WHERE id = " + ids[0])


# Bad: the parsed JSON body is a source
def bad_sql_from_get_json(cur):
    body = request.get_json()
    # ruleid: cra-python-taint-sql-inject
    cur.execute("SELECT * FROM users WHERE name = '" + body["name"] + "'")


# Bad: a value stored in a configparser option and read back from the same
# section and option name is still tainted
def bad_sql_configparser_same_key(cur):
    import configparser

    param = request.form.get("name")
    conf = configparser.ConfigParser()
    conf.add_section("section")
    conf.set("section", "keyA", "a-Value")
    conf.set("section", "keyB", param)
    bar = conf.get("section", "keyB")
    # ruleid: cra-python-taint-sql-inject
    cur.execute("SELECT * FROM users WHERE name = '" + bar + "'")


# Safe: a different option is read back, so the tainted value is not the one used
def ok_sql_configparser_other_key(cur):
    import configparser

    param = request.form.get("name")
    conf = configparser.ConfigParser()
    conf.add_section("section")
    conf.set("section", "keyA", "a-Value")
    conf.set("section", "keyB", param)
    bar = conf.get("section", "keyA")
    # ok: cra-python-taint-sql-inject
    cur.execute("SELECT * FROM users WHERE name = '" + bar + "'")
