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
