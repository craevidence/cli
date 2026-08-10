<?php
function requested_url(): string {
    return $_GET["url"];
}

function bad_across_helper($handle): void {
    $target = requested_url();
    // ruleid: cra-php-curl-url-superglobal-taint
    curl_setopt($handle, CURLOPT_URL, $target);
}

function bad($handle): void {
    $target = $_POST["target"];
    // ruleid: cra-php-curl-url-superglobal-taint
    curl_setopt($handle, CURLOPT_URL, $target);
}

function bad_curl_init() {
    $target = $_COOKIE["target"];
    // ruleid: cra-php-curl-url-superglobal-taint
    return curl_init($target);
}

function bad_whole_superglobal() {
    $input = $_GET;
    $target = $input["target"];
    // ruleid: cra-php-curl-url-superglobal-taint
    return curl_init($target);
}

function good($handle): void {
    // ok: cra-php-curl-url-superglobal-taint
    curl_setopt($handle, CURLOPT_URL, "https://updates.example.com/manifest.json");
}
