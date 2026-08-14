<?php
namespace Application;

function unserialize(mixed $value): mixed
{
    return $value;
}

// ok: cra-php-global-unserialize-superglobal
$local = unserialize($_POST['payload']);

// ruleid: cra-php-global-unserialize-superglobal
$global = \unserialize($_COOKIE['session']);

$request = $_REQUEST;
// ruleid: cra-php-global-unserialize-superglobal
$indirect = \unserialize($request['payload'], ['allowed_classes' => false]);

// ruleid: cra-php-global-unserialize-superglobal
$mixedCase = \UNSERIALIZE($_GET['payload']);

// ruleid: cra-php-global-unserialize-superglobal
$server = \unserialize($_SERVER['HTTP_X_SERIALIZED']);

// ok: cra-php-global-unserialize-superglobal
$json = \json_decode($_GET['payload'], true);

// ok: cra-php-global-unserialize-superglobal
$qualified = Application\unserialize($_GET['payload']);

// ok: cra-php-global-unserialize-superglobal
$relative = namespace\unserialize($_GET['payload']);

$trusted = 's:5:"value";';
// ok: cra-php-global-unserialize-superglobal
$safeGlobal = \unserialize($trusted) + strlen($_GET['not_the_argument']);

// ok: cra-php-global-unserialize-superglobal
$structuredServerValue = \unserialize($_SERVER['REMOTE_ADDR']);

// The text \unserialize($_GET['comment']) is not executable.
$text = '\\unserialize($_GET["string"])';
