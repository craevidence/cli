import flask
from flask import request


def requested_expression():
    return request.args.get("expr")


def bad_eval_across_helper():
    expression = requested_expression()
    # ruleid: cra-python-taint-eval-exec
    eval(expression)


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


# Bad: qualified flask.request source -> eval (sink)
def bad_eval_from_qualified_request():
    expr = flask.request.args.get("expr")
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


# Bad: the value is read with subscript access rather than get()
def bad_subscript_args_to_eval():
    expression = request.args["expr"]
    # ruleid: cra-python-taint-eval-exec
    eval(expression)


# Safe: validated to be a quoted string literal, so it can only evaluate to a
# string constant
def ok_eval_quoted_literal_guard():
    code = request.args.get("expr")
    if not code.startswith("'") or not code.endswith("'") or "'" in code[1:-1]:
        return "not a literal"
    # ok: cra-python-taint-eval-exec
    eval(code)


# Bad: the ends are checked but a quote between them can still close the literal
# and start a call
def bad_eval_partial_quote_guard():
    code = request.args.get("expr")
    if not code.startswith("'") or not code.endswith("'"):
        return "not a literal"
    # ruleid: cra-python-taint-eval-exec
    eval(code)


# Bad: a prefix check leaves the rest of the value free
def bad_eval_prefix_guard():
    code = request.args.get("expr")
    if not code.startswith("safe_"):
        return "rejected"
    # ruleid: cra-python-taint-eval-exec
    eval(code)


# Bad: multi-value accessor is a source
def bad_eval_from_getlist():
    values = request.args.getlist("expr")
    # ruleid: cra-python-taint-eval-exec
    eval(values[0])


# Bad: the raw query string is a source
def bad_eval_from_query_string():
    raw = request.query_string
    # ruleid: cra-python-taint-eval-exec
    exec(raw)


# Bad: a value stored in a configparser option and read back from the same
# section and option name is still tainted
def bad_eval_configparser_same_key():
    import configparser

    param = request.form.get("expr")
    conf = configparser.ConfigParser()
    conf.add_section("section")
    conf.set("section", "keyA", "a-Value")
    conf.set("section", "keyB", param)
    bar = conf.get("section", "keyB")
    # ruleid: cra-python-taint-eval-exec
    exec(bar)


# Safe: a different option is read back, so the tainted value is not the one used
def ok_eval_configparser_other_key():
    import configparser

    param = request.form.get("expr")
    conf = configparser.ConfigParser()
    conf.add_section("section")
    conf.set("section", "keyA", "a-Value")
    conf.set("section", "keyB", param)
    bar = conf.get("section", "keyA")
    # ok: cra-python-taint-eval-exec
    exec(bar)
