<?php
function bad(): void {
    // ruleid: cra-php-echo-superglobal-taint
    print $_POST["message"];
}

function bad_indirect(): void {
    $message = $_GET["message"];
    // ruleid: cra-php-echo-superglobal-taint
    echo $message;
}

function bad_whole_superglobal(): void {
    $input = $_GET;
    $message = $input["message"];
    // ruleid: cra-php-echo-superglobal-taint
    echo $message;
}

function good(): void {
    $title = $_GET["title"];
    // ok: cra-php-echo-superglobal-taint
    echo htmlspecialchars($title, ENT_QUOTES | ENT_SUBSTITUTE, "UTF-8");
}

function good_htmlentities(): void {
    $title = $_GET["title"];
    // ok: cra-php-echo-superglobal-taint
    echo htmlentities($title, ENT_QUOTES | ENT_SUBSTITUTE, "UTF-8");
}
