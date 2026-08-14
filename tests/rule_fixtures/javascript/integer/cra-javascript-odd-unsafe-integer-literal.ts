// ok: cra-javascript-odd-unsafe-integer-literal
const safeBoundary: number = 9007199254740991;
// ok: cra-javascript-odd-unsafe-integer-literal
const safeNegativeBoundary: number = -9007199254740991;
// ok: cra-javascript-odd-unsafe-integer-literal
const safeExactEven: number = 9007199254740992;
// ok: cra-javascript-odd-unsafe-integer-literal
const safeHexadecimal: number = 0x20000000000000;
// ok: cra-javascript-odd-unsafe-integer-literal
const safeBigInt: bigint = 9007199254740993n;
// ok: cra-javascript-odd-unsafe-integer-literal
const safeString: string = "9007199254740993";

// ruleid: cra-javascript-odd-unsafe-integer-literal
const unsafeDecimal: number = 9007199254740993;
// ruleid: cra-javascript-odd-unsafe-integer-literal
const unsafeNegativeDecimal: number = -9007199254740993;
// ruleid: cra-javascript-odd-unsafe-integer-literal
const unsafeSeparated: number = 9_007_199_254_740_993;
// ruleid: cra-javascript-odd-unsafe-integer-literal
const unsafeHexadecimal: number = 0x20000000000001;
// ruleid: cra-javascript-odd-unsafe-integer-literal
const unsafeBinary: number = 0b100000000000000000000000000000000000000000000000000001;
// ruleid: cra-javascript-odd-unsafe-integer-literal
const unsafeOctal: number = 0o400000000000000001;

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
