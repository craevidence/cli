<?php
function bad_md5(): string {
    // ruleid: cra-php-superglobal-password-md5
    return md5($_POST["password"]);
}

function bad_sha1(): string {
    // ruleid: cra-php-superglobal-password-md5
    return sha1($_REQUEST['passwd']);
}

function bad_get(): string {
    // ruleid: cra-php-superglobal-password-md5
    return md5($_GET['pwd']);
}

function bad_prefixed_password(): string {
    // ruleid: cra-php-superglobal-password-md5
    return md5($_POST['user_password']);
}

function bad_camel_case_password(): string {
    // ruleid: cra-php-superglobal-password-md5
    return sha1($_REQUEST["confirmPassword"]);
}

function good(): string {
    // ok: cra-php-superglobal-password-md5
    return password_hash($_POST["password"], PASSWORD_ARGON2ID);
}

function checksum(): string {
    // ok: cra-php-superglobal-password-md5
    return md5($_POST["file_contents"]);
}
