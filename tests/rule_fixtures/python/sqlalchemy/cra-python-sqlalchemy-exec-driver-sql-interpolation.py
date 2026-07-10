ALLOWED_TABLES = {"users", "orders"}


def count_fstring(conn, table):
    # ruleid: cra-python-sqlalchemy-exec-driver-sql-interpolation
    return conn.exec_driver_sql(f"SELECT count(*) FROM {table}").scalar()


def count_format(conn, table):
    # ruleid: cra-python-sqlalchemy-exec-driver-sql-interpolation
    return conn.exec_driver_sql("SELECT count(*) FROM {}".format(table)).scalar()


def count_percent(conn, table):
    # ruleid: cra-python-sqlalchemy-exec-driver-sql-interpolation
    return conn.exec_driver_sql("SELECT count(*) FROM %s" % table).scalar()


def count_concat(conn, table):
    # ruleid: cra-python-sqlalchemy-exec-driver-sql-interpolation
    return conn.exec_driver_sql("SELECT count(*) FROM " + table).scalar()


def count_concat_left(conn, verb):
    # ruleid: cra-python-sqlalchemy-exec-driver-sql-interpolation
    return conn.exec_driver_sql(verb + " count(*) FROM users").scalar()


def safe_placeholder(conn, uid):
    # ok: cra-python-sqlalchemy-exec-driver-sql-interpolation
    return conn.exec_driver_sql("SELECT * FROM users WHERE id = %s", (uid,)).scalar()


def safe_static(conn):
    # ok: cra-python-sqlalchemy-exec-driver-sql-interpolation
    return conn.exec_driver_sql("SELECT count(*) FROM users").scalar()


def safe_static_concat(conn):
    # ok: cra-python-sqlalchemy-exec-driver-sql-interpolation
    return conn.exec_driver_sql("SELECT count(*) " + "FROM users").scalar()
