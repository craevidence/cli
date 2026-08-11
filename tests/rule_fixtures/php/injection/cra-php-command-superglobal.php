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

// A value escaped for the shell, or constrained to a number or a boolean,
// cannot carry shell metacharacters.

function ok_escapeshellarg(): void {
    $target = escapeshellarg($_GET['target']);
    // ok: cra-php-command-superglobal
    system('ls ' . $target);
}

function ok_escapeshellcmd(): void {
    $command = escapeshellcmd($_POST['command']);
    // ok: cra-php-command-superglobal
    system($command);
}

function ok_intval(): void {
    $signal = intval($_GET['signal']);
    // ok: cra-php-command-superglobal
    exec('kill -' . $signal . ' 1');
}

function ok_floatval(): void {
    $size = floatval($_GET['size']);
    // ok: cra-php-command-superglobal
    system('find / -size ' . $size);
}

function ok_doubleval(): void {
    $size = doubleval($_GET['size']);
    // ok: cra-php-command-superglobal
    system('find / -size ' . $size);
}

function ok_boolval(): void {
    $flag = boolval($_GET['flag']);
    // ok: cra-php-command-superglobal
    system('report ' . $flag);
}

function ok_int_cast(): void {
    $count = (int) $_GET['count'];
    // ok: cra-php-command-superglobal
    system('head -n ' . $count . ' /var/log/app.log');
}

function ok_settype(): void {
    $count = $_GET['count'];
    settype($count, 'integer');
    // ok: cra-php-command-superglobal
    system('head -n ' . $count . ' /var/log/app.log');
}

function ok_filter_var_validate_int(): void {
    $count = filter_var($_GET['count'], FILTER_VALIDATE_INT);
    // ok: cra-php-command-superglobal
    system('head -n ' . $count . ' /var/log/app.log');
}

function ok_filter_var_sanitize_number(): void {
    $size = filter_var($_GET['size'], FILTER_SANITIZE_NUMBER_INT);
    // ok: cra-php-command-superglobal
    system('find / -size ' . $size);
}

function ok_arithmetic_coercion(): void {
    $size = $_GET['size'];
    $size += 0;
    // ok: cra-php-command-superglobal
    system('find / -size ' . $size);
}

// A regular expression that accepts everything is still a flaw, so validation
// by pattern is not treated as a sanitizer.
function bad_permissive_pattern(): void {
    $command = $_GET['command'];
    if (preg_match('/^.*$/', $command) === 1) {
        // ruleid: cra-php-command-superglobal
        system($command);
    }
}
