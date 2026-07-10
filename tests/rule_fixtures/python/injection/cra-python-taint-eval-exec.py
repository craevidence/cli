from flask import request


# Bad: request.args tainted -> eval (sink)
def bad_eval_from_args():
    code = request.args.get("expr")
    # ruleid: cra-python-taint-eval-exec
    eval(code)


# Bad: request.form tainted -> eval (sink)
def bad_eval_from_form():
    code = request.form.get("expr")
    # ruleid: cra-python-taint-eval-exec
    eval(code)


# Bad: request.json tainted -> exec (sink)
def bad_exec_from_json():
    payload = request.json
    # ruleid: cra-python-taint-eval-exec
    exec(payload)


# Bad: request.data tainted -> exec (sink)
def bad_exec_from_data():
    raw = request.data
    # ruleid: cra-python-taint-eval-exec
    exec(raw)


# Bad: request.headers tainted -> eval (sink)
def bad_eval_from_header():
    hdr = request.headers.get("X-Expr")
    # ruleid: cra-python-taint-eval-exec
    eval(hdr)


# Bad: request.cookies tainted -> eval (sink)
def bad_eval_from_cookie():
    ck = request.cookies.get("expr")
    # ruleid: cra-python-taint-eval-exec
    eval(ck)


# Bad: input() tainted -> eval (sink)
def bad_eval_from_input():
    expr = input("Enter expression: ")
    # ruleid: cra-python-taint-eval-exec
    eval(expr)


# Safe: constant string to eval -- no taint from user input
def ok_eval_constant():
    # ok: cra-python-taint-eval-exec
    eval("1 + 1")


# Safe: request value used only in JSON response, not eval/exec
def ok_request_no_eval():
    name = request.args.get("name")
    # ok: cra-python-taint-eval-exec
    return str(name)
