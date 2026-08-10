<?php
function requested_path(): string {
    return $_GET["path"];
}

function bad_across_helper(): void {
    $path = requested_path();
    // ruleid: cra-php-file-superglobal-taint
    readfile($path);
}

function bad(): void {
    $path = $_POST["path"];
    // ruleid: cra-php-file-superglobal-taint
    fopen($path, "rb");
}

function bad_file_get_contents(): string {
    $path = $_REQUEST["path"];
    // ruleid: cra-php-file-superglobal-taint
    return file_get_contents($path);
}

function bad_whole_superglobal(): string {
    $input = $_GET;
    $path = $input["path"];
    // ruleid: cra-php-file-superglobal-taint
    return file_get_contents($path);
}

function good(): void {
    // ok: cra-php-file-superglobal-taint
    readfile("/srv/app/public/manual.pdf");
}


// Bad: a client controlled $_SERVER entry is a source too
function bad_server_header_superglobal()
{
    // ruleid: cra-php-file-superglobal-taint
    $h = fopen($_SERVER["PATH_INFO"], "r");
}
