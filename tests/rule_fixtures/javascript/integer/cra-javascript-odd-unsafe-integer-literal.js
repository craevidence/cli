// ok: cra-javascript-odd-unsafe-integer-literal
const safeBoundary = 9007199254740991;
// ok: cra-javascript-odd-unsafe-integer-literal
const safeNegativeBoundary = -9007199254740991;
// ok: cra-javascript-odd-unsafe-integer-literal
const safeExactEven = 9007199254740992;
// ok: cra-javascript-odd-unsafe-integer-literal
const safeHexadecimal = 0x20000000000000;
// ok: cra-javascript-odd-unsafe-integer-literal
const safeBigInt = 9007199254740993n;
// ok: cra-javascript-odd-unsafe-integer-literal
const safeString = "9007199254740993";

// ruleid: cra-javascript-odd-unsafe-integer-literal
const unsafeDecimal = 9007199254740993;
// ruleid: cra-javascript-odd-unsafe-integer-literal
const unsafeNegativeDecimal = -9007199254740993;
// ruleid: cra-javascript-odd-unsafe-integer-literal
const unsafeSeparated = 9_007_199_254_740_993;
// ruleid: cra-javascript-odd-unsafe-integer-literal
const unsafeHexadecimal = 0x20000000000001;
// ruleid: cra-javascript-odd-unsafe-integer-literal
const unsafeBinary = 0b100000000000000000000000000000000000000000000000000001;
// ruleid: cra-javascript-odd-unsafe-integer-literal
const unsafeOctal = 0o400000000000000001;

void safeBoundary;
void safeNegativeBoundary;
void safeExactEven;
void safeHexadecimal;
void safeBigInt;
void safeString;
void unsafeDecimal;
void unsafeNegativeDecimal;
void unsafeSeparated;
void unsafeHexadecimal;
void unsafeBinary;
void unsafeOctal;
