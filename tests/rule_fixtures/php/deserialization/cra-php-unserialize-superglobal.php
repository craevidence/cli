<?php
// ruleid: cra-php-unserialize-superglobal
$object = unserialize($_COOKIE['session']);

// ruleid: cra-php-unserialize-superglobal
$requested = unserialize($_REQUEST['payload']);

function bad_indirect() {
    $request = $_POST;
    $payload = $request['payload'];
    // ruleid: cra-php-unserialize-superglobal
    return unserialize($payload);
}

// ok: cra-php-unserialize-superglobal
$data = json_decode($_COOKIE['session'], true, 8, JSON_THROW_ON_ERROR);


// Bad: a client controlled $_SERVER entry is a source too
function bad_server_header_unserialize()
{
    // ruleid: cra-php-unserialize-superglobal
    $o = unserialize($_SERVER["HTTP_X_DATA"]);
}
