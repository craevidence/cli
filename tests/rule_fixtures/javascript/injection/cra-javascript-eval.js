// Bad: eval with dynamic argument
function badEvalDynamic(userInput) {
    // ruleid: cra-javascript-eval
    eval(userInput);
}

// Bad: eval with concatenated string
function badEvalConcat(name) {
    // ruleid: cra-javascript-eval
    eval("console.log(" + name + ")");
}

// Safe: JSON.parse for data -- no code execution
function okJsonParse(raw) {
    // ok: cra-javascript-eval
    return JSON.parse(raw);
}

// Safe: structured dispatch instead of eval
function okStructuredDispatch(action, handlers) {
    // ok: cra-javascript-eval
    const fn = handlers[action];
    if (typeof fn === "function") {
        fn();
    }
}
