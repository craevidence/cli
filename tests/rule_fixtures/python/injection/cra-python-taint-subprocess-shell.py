import subprocess

from flask import request


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


# Safe: list of arguments with shell=False -- no injection surface
def ok_run_list():
    filename = request.args.get("file")
    # ok: cra-python-taint-subprocess-shell
    subprocess.run(["ls", "-l", filename])


# Safe: fixed command as a list with shell=False (no tainted value reaches a shell)
def ok_run_fixed_command():
    # ok: cra-python-taint-subprocess-shell
    subprocess.run(["echo", "hello"], shell=False)
