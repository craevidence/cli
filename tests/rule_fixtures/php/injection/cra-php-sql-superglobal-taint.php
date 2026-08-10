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
