<?php
// ruleid: cra-php-command-superglobal
exec($_GET['command']);

// ruleid: cra-php-command-superglobal
system($_POST['command']);

// ruleid: cra-php-command-superglobal
shell_exec($_REQUEST['command']);

// ruleid: cra-php-command-superglobal
passthru($_COOKIE['command']);

// ruleid: cra-php-command-superglobal
popen($_GET['command'], 'r');

function bad_indirect(): void {
    $command = $_GET;
    $command = $command['command'];
    // ruleid: cra-php-command-superglobal
    exec($command);
}

function bad_proc_open(): void {
    $command = $_POST['command'];
    // ruleid: cra-php-command-superglobal
    proc_open($command, [], $pipes);
}

function bad_backticks(): string {
    $command = $_REQUEST['command'];
    // ruleid: cra-php-command-superglobal
    return `$command`;
}

// ok: cra-php-command-superglobal
exec('/usr/bin/status');


// Bad: a client controlled $_SERVER entry is a source too
function bad_server_header_command()
{
    // ruleid: cra-php-command-superglobal
    system($_SERVER["HTTP_X_COMMAND"]);
}
