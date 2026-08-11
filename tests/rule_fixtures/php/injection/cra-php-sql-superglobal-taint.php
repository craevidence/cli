<?php
function requested_name(): string {
    return $_GET["name"];
}

function bad_across_helper(PDO $database): void {
    $name = requested_name();
    $query = "SELECT * FROM users WHERE name = '" . $name . "'";
    // ruleid: cra-php-sql-superglobal-taint
    $database->query($query);
}

function bad(PDO $database): void {
    $query = "SELECT * FROM users WHERE id = " . $_POST["id"];
    // ruleid: cra-php-sql-superglobal-taint
    $database->exec($query);
}

function bad_dynamic_prepare(PDO $database): void {
    $table = $_GET["table"];
    $query = "SELECT * FROM " . $table . " WHERE id = ?";
    // ruleid: cra-php-sql-superglobal-taint
    $database->prepare($query);
}

function bad_whole_superglobal(PDO $database): void {
    $input = $_GET;
    $table = $input["table"];
    // ruleid: cra-php-sql-superglobal-taint
    $database->query("SELECT * FROM " . $table);
}

function good(PDO $database): void {
    $name = $_GET["name"];
    $statement = $database->prepare("SELECT * FROM users WHERE name = ?");
    // ok: cra-php-sql-superglobal-taint
    $statement->execute([$name]);
}

function good_intval(PDO $database): void {
    $id = intval($_GET["id"]);
    // ok: cra-php-sql-superglobal-taint
    $database->query("SELECT * FROM users WHERE id = " . $id);
}

function good_filter_var(PDO $database): void {
    $id = filter_var($_GET["id"], FILTER_VALIDATE_INT);
    // ok: cra-php-sql-superglobal-taint
    $database->query("SELECT * FROM users WHERE id = " . $id);
}


// Bad: a client controlled $_SERVER entry is a source too
function bad_server_header_superglobal()
{
    // ruleid: cra-php-sql-superglobal-taint
    mysqli_query($conn, "SELECT * FROM t WHERE ua = '" . $_SERVER["HTTP_USER_AGENT"] . "'");
}

// Legacy and PostgreSQL execution functions are sinks too.

function bad_legacy_mysql_query(): void {
    $id = $_GET['id'];
    // ruleid: cra-php-sql-superglobal-taint
    mysql_query("SELECT * FROM users WHERE id = " . $id);
}

function bad_pg_query($conn): void {
    $name = $_POST['name'];
    // ruleid: cra-php-sql-superglobal-taint
    pg_query($conn, "SELECT * FROM users WHERE name = '" . $name . "'");
}

function bad_mysqli_multi_query($db): void {
    $id = $_GET['id'];
    // ruleid: cra-php-sql-superglobal-taint
    mysqli_multi_query($db, "SELECT * FROM users WHERE id = " . $id);
}

// Escaping only protects a value written inside quotes. Here it is not, so
// 1 OR 1=1 passes through and this must still report.
function bad_escaped_but_unquoted(): void {
    $id = mysql_real_escape_string($_GET['id']);
    // ruleid: cra-php-sql-superglobal-taint
    mysql_query("SELECT * FROM student WHERE id = " . $id);
}

// A value constrained to a number cannot carry SQL syntax.

function ok_floatval($db): void {
    $price = floatval($_GET['price']);
    // ok: cra-php-sql-superglobal-taint
    mysqli_query($db, "SELECT * FROM items WHERE price < " . $price);
}

function ok_doubleval($db): void {
    $price = doubleval($_GET['price']);
    // ok: cra-php-sql-superglobal-taint
    mysqli_query($db, "SELECT * FROM items WHERE price < " . $price);
}

function ok_boolval($db): void {
    $active = boolval($_GET['active']);
    // ok: cra-php-sql-superglobal-taint
    mysqli_query($db, "SELECT * FROM users WHERE active = " . $active);
}

function ok_int_cast($db): void {
    $id = (int) $_GET['id'];
    // ok: cra-php-sql-superglobal-taint
    mysqli_query($db, "SELECT * FROM users WHERE id = " . $id);
}

function ok_settype($db): void {
    $id = $_GET['id'];
    settype($id, 'integer');
    // ok: cra-php-sql-superglobal-taint
    mysqli_query($db, "SELECT * FROM users WHERE id = " . $id);
}

function ok_arithmetic_coercion($db): void {
    $id = $_GET['id'];
    $id += 0;
    // ok: cra-php-sql-superglobal-taint
    mysqli_query($db, "SELECT * FROM users WHERE id = " . $id);
}

function ok_filter_var_sanitize_number($db): void {
    $id = filter_var($_GET['id'], FILTER_SANITIZE_NUMBER_INT);
    // ok: cra-php-sql-superglobal-taint
    mysqli_query($db, "SELECT * FROM users WHERE id = " . $id);
}

function ok_pdo_quote($pdo): void {
    $name = $pdo->quote($_GET['name']);
    // ok: cra-php-sql-superglobal-taint
    $pdo->query("SELECT * FROM users WHERE name = " . $name);
}
