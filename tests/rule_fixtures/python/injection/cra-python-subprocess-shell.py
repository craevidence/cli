import subprocess


# Bad: subprocess.run with shell=True
def bad_run_shell(cmd):
    # ruleid: cra-python-subprocess-shell
    subprocess.run(cmd, shell=True)


# Bad: subprocess.call with shell=True
def bad_call_shell(cmd):
    # ruleid: cra-python-subprocess-shell
    subprocess.call(cmd, shell=True)


# Bad: subprocess.Popen with shell=True
def bad_popen_shell(cmd):
    # ruleid: cra-python-subprocess-shell
    subprocess.Popen(cmd, shell=True)


# Bad: subprocess.check_output with shell=True
def bad_check_output_shell(cmd):
    # ruleid: cra-python-subprocess-shell
    subprocess.check_output(cmd, shell=True)


# Safe: list of arguments, shell=False (default)
def ok_run_list(filename):
    # ok: cra-python-subprocess-shell
    subprocess.run(["ls", "-l", filename])


# Safe: explicit shell=False
def ok_run_shell_false(filename):
    # ok: cra-python-subprocess-shell
    subprocess.run(["grep", "pattern", filename], shell=False)


# Safe: the whole command is fixed in the source, so nothing can be injected
def ok_run_shell_literal():
    # ok: cra-python-subprocess-shell
    subprocess.run("ls -l", shell=True)


# Bad: getoutput always runs the command through a shell
def bad_getoutput(cmd):
    # ruleid: cra-python-subprocess-shell
    subprocess.getoutput(cmd)


# Bad: the argument list starts a shell and passes the command after -c
def bad_shell_argv_literal(cmd):
    # ruleid: cra-python-subprocess-shell
    subprocess.run(["/bin/sh", "-c", cmd])


# Bad: the same shell argument list built with append
def bad_shell_argv_appended(cmd):
    argv = []
    argv.append("bash")
    argv.append("-c")
    # ruleid: cra-python-subprocess-shell
    argv.append(cmd)
    subprocess.run(argv)


# Safe: -c belongs to a program that is not a shell
def ok_non_shell_dash_c(value):
    # ok: cra-python-subprocess-shell
    subprocess.run(["git", "-c", value, "status"])


# Safe: a shell command fixed in the source
def ok_shell_argv_literal_command():
    # ok: cra-python-subprocess-shell
    subprocess.run(["/bin/sh", "-c", "ls -l"])
