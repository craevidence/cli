import childProcess from "node:child_process";
import * as childProcessNamespace from "child_process";
import { exec as runCommand } from "node:child_process";

function listPath(path: string): void {
    // ruleid: cra-javascript-exec-injection
    childProcess.exec("ls " + path);
}

function listPathWithoutShell(path: string): void {
    // ok: cra-javascript-exec-injection
    childProcess.execFile("ls", [path]);
}

function listPathNamespace(path: string): void {
    // ruleid: cra-javascript-exec-injection
    childProcessNamespace.execSync("ls " + path);
}

function listPathNamedAlias(path: string): void {
    // ruleid: cra-javascript-exec-injection
    runCommand("ls " + path);
}
