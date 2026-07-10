import sqlite3


def get_cursor():
    conn = sqlite3.connect(":memory:")
    return conn.cursor()


# Branch 1: % formatting in execute()
def bad_sql_percent(cur, username):
    # ruleid: cra-python-sql-injection
    cur.execute("SELECT * FROM users WHERE name = '%s'" % username)


# Branch 2: .format() in execute()
def bad_sql_format(cur, username):
    # ruleid: cra-python-sql-injection
    cur.execute("SELECT * FROM users WHERE name = '{}'".format(username))


# Branch 3: f-string in execute()
def bad_sql_fstring(cur, username):
    # ruleid: cra-python-sql-injection
    cur.execute(f"SELECT * FROM users WHERE name = '{username}'")


# Safe: parameterized query -- value passed as second argument
def ok_sql_parameterized(cur, username):
    # ok: cra-python-sql-injection
    cur.execute("SELECT * FROM users WHERE name = ?", (username,))


# Safe: no user input in the query string
def ok_sql_literal(cur):
    # ok: cra-python-sql-injection
    cur.execute("SELECT COUNT(*) FROM users")
