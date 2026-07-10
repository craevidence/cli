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
