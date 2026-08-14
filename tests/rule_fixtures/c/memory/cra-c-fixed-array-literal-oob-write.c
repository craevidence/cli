typedef unsigned char uint8_t;

void direct_assignment(int value) {
    uint8_t buffer[4];
    // ok: cra-c-fixed-array-literal-oob-write
    buffer[3] = (uint8_t)value;
    // ruleid: cra-c-fixed-array-literal-oob-write
    buffer[4] = (uint8_t)value;
}

void excluded_forms(int value, int index) {
    uint8_t buffer[4];
    // ok: cra-c-fixed-array-literal-oob-write
    buffer[index] = (uint8_t)value;
    // ok: cra-c-fixed-array-literal-oob-write
    buffer[4U] = (uint8_t)value;
    // ok: cra-c-fixed-array-literal-oob-write
    buffer[0x4] = (uint8_t)value;
    // ok: cra-c-fixed-array-literal-oob-write
    buffer[-1] = (uint8_t)value;
    // ok: cra-c-fixed-array-literal-oob-write
    buffer[4] += (uint8_t)value;
    // ok: cra-c-fixed-array-literal-oob-write
    (void)buffer[4];
}
