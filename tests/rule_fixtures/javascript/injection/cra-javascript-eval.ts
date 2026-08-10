function parseDynamicExpression(userInput: string): unknown {
    // ruleid: cra-javascript-eval
    return eval(userInput);
}

function parseStructuredData(raw: string): unknown {
    // ok: cra-javascript-eval
    return JSON.parse(raw);
}
