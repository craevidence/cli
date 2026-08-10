const { exec, execSync } = require("child_process");
const cp = require("child_process");

// Branch 1: cp.exec with concatenated command
function badExecConcat(filename) {
    // ruleid: cra-javascript-exec-injection
    cp.exec("ls " + filename, (err, stdout) => { console.log(stdout); });
}

// Branch 2: cp.execSync with concatenated command
function badExecSyncConcat(dir) {
    // ruleid: cra-javascript-exec-injection
    cp.execSync("find " + dir);
}

function badExecTemplate(dir) {
    // ruleid: cra-javascript-exec-injection
    cp.exec(`find ${dir}`);
}

// Branch 3: require('child_process').exec inline
function badInlineRequireExec(arg) {
    // ruleid: cra-javascript-exec-injection
    require("child_process").exec("ping " + arg);
}

// Branch 4: require('child_process').execSync inline
function badInlineRequireExecSync(arg) {
    // ruleid: cra-javascript-exec-injection
    require("child_process").execSync("ping " + arg);
}

function badDestructuredExec(arg) {
    // ruleid: cra-javascript-exec-injection
    exec("ping " + arg);
}

function badDestructuredExecSync(arg) {
    // ruleid: cra-javascript-exec-injection
    execSync("ping " + arg);
}

function okRegExpExec(value) {
    const expression = /prefix/;
    // ok: cra-javascript-exec-injection
    return expression.exec("prefix " + value);
}

function okObjectExec(value, database) {
    // ok: cra-javascript-exec-injection
    return database.exec("SELECT " + value);
}

// Safe: execFile with argument array -- no shell interpolation
function okExecFile(filename) {
    const { execFile } = require("child_process");
    // ok: cra-javascript-exec-injection
    execFile("ls", [filename], (err, stdout) => { console.log(stdout); });
}

// Safe: spawn with argument array
function okSpawn(dir) {
    const { spawn } = require("child_process");
    // ok: cra-javascript-exec-injection
    spawn("find", [dir, "-type", "f"]);
}

// Bad: the module is bound with var rather than const
function badVarRequire(host) {
    var cp = require("child_process");
    // ruleid: cra-javascript-exec-injection
    cp.exec("ping " + host);
}

// Bad: the module is bound with let
function badLetRequire(host) {
    let cp = require("child_process");
    // ruleid: cra-javascript-exec-injection
    cp.exec("ping " + host);
}

// Bad: the binding is one of several declarators in a single var statement
function badMultiDeclaratorRequire(host) {
    var cp = require("child_process"),
        os = require("os");
    // ruleid: cra-javascript-exec-injection
    cp.exec("ping " + host + " " + os.hostname());
}

// Safe: var binding, argument array instead of a command string
function okVarRequireExecFile(filename) {
    var cp = require("child_process");
    // ok: cra-javascript-exec-injection
    cp.execFile("ls", [filename], (err, stdout) => { console.log(stdout); });
}

// Bad: the function is taken off the module with a member access
function badMemberAccessBinding(host) {
    var run = require("child_process").exec;
    // ruleid: cra-javascript-exec-injection
    run("ping " + host);
}

// Bad: single-name ESM import rather than a pair
function badSingleNameImportPlaceholder(host) {
    // ruleid: cra-javascript-exec-injection
    require("child_process").execSync("ping " + host);
}
