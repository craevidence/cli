import os
import subprocess

import flask
from flask import request


def requested_command():
    return request.args.get("cmd")


def bad_run_across_helper():
    command = requested_command()
    # ruleid: cra-python-taint-subprocess-shell
    subprocess.run(command, shell=True)


# Bad: request.args tainted -> subprocess.run with shell=True (sink)
def bad_run_from_args():
    cmd = request.args.get("cmd")
    # ruleid: cra-python-taint-subprocess-shell
    subprocess.run(cmd, shell=True)


# Bad: request.form tainted -> subprocess.call with shell=True (sink)
def bad_call_from_form():
    cmd = request.form.get("action")
    # ruleid: cra-python-taint-subprocess-shell
    subprocess.call(cmd, shell=True)


# Bad: request.json tainted -> subprocess.Popen with shell=True (sink)
def bad_popen_from_json():
    payload = request.json
    # ruleid: cra-python-taint-subprocess-shell
    subprocess.Popen(payload, shell=True)


# Bad: request.cookies tainted -> subprocess.check_output with shell=True (sink)
def bad_check_output_from_cookie():
    cookie_cmd = request.cookies.get("run")
    # ruleid: cra-python-taint-subprocess-shell
    subprocess.check_output(cookie_cmd, shell=True)


# Bad: request.data tainted -> subprocess.run with shell=True (sink)
def bad_run_from_data():
    raw = request.data
    # ruleid: cra-python-taint-subprocess-shell
    subprocess.run(raw, shell=True)


# Bad: request.headers tainted -> subprocess.run with shell=True (sink)
def bad_run_from_header():
    hdr = request.headers.get("X-Command")
    # ruleid: cra-python-taint-subprocess-shell
    subprocess.run(hdr, shell=True)


# Bad: input() tainted -> subprocess.run with shell=True (sink)
def bad_run_from_input():
    cmd = input("Enter command: ")
    # ruleid: cra-python-taint-subprocess-shell
    subprocess.run(cmd, shell=True)


# Bad: qualified flask.request source -> shell sink
def bad_run_from_qualified_request():
    cmd = flask.request.args.get("cmd")
    # ruleid: cra-python-taint-subprocess-shell
    subprocess.run(cmd, shell=True)


def bad_os_system():
    cmd = request.args.get("cmd")
    # ruleid: cra-python-taint-subprocess-shell
    os.system(cmd)


def bad_os_popen():
    cmd = request.form.get("cmd")
    # ruleid: cra-python-taint-subprocess-shell
    os.popen(cmd)


def ok_os_system_constant():
    # ok: cra-python-taint-subprocess-shell
    os.system("true")


# Safe: list of arguments with shell=False -- no injection surface
def ok_run_list():
    filename = request.args.get("file")
    # ok: cra-python-taint-subprocess-shell
    subprocess.run(["ls", "-l", filename])


# Safe: fixed command as a list with shell=False (no tainted value reaches a shell)
def ok_run_fixed_command():
    # ok: cra-python-taint-subprocess-shell
    subprocess.run(["echo", "hello"], shell=False)


# Bad: the value is read with subscript access rather than get()
def bad_subscript_args_to_shell():
    command = request.args["cmd"]
    # ruleid: cra-python-taint-subprocess-shell
    subprocess.run(command, shell=True)


# Bad: form subscript access
def bad_subscript_form_to_shell():
    command = request.form["cmd"]
    # ruleid: cra-python-taint-subprocess-shell
    subprocess.run(command, shell=True)


# Bad: the shell is started through the argument list rather than shell=True
def bad_shell_argv_literal():
    cmd = request.args.get("cmd")
    # ruleid: cra-python-taint-subprocess-shell
    subprocess.run(["/bin/sh", "-c", cmd])


# Bad: the same shell argument list built with append
def bad_shell_argv_appended():
    cmd = request.form.get("cmd")
    argv = []
    argv.append("sh")
    argv.append("-c")
    # ruleid: cra-python-taint-subprocess-shell
    argv.append(f"echo {cmd}")
    subprocess.run(argv)


# Bad: getoutput always runs the command through a shell
def bad_getoutput():
    cmd = request.args.get("cmd")
    # ruleid: cra-python-taint-subprocess-shell
    subprocess.getoutput(cmd)


# Bad: multi-value accessor is a source
def bad_run_from_getlist():
    values = request.args.getlist("cmd")
    # ruleid: cra-python-taint-subprocess-shell
    subprocess.run(values[0], shell=True)


# Bad: the form key name is chosen by the client
def bad_run_from_form_key():
    for name in request.form.keys():
        # ruleid: cra-python-taint-subprocess-shell
        subprocess.run(name, shell=True)


# Safe: -c belongs to a program that is not a shell
def ok_non_shell_dash_c():
    value = request.args.get("value")
    # ok: cra-python-taint-subprocess-shell
    subprocess.run(["git", "-c", value, "status"])
