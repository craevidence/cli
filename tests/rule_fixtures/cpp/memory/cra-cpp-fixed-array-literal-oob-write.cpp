#include <cstdint>

void direct_assignment(int value) {
    uint8_t buffer[4];
    // ok: cra-cpp-fixed-array-literal-oob-write
    buffer[3] = static_cast<uint8_t>(value);
    // ruleid: cra-cpp-fixed-array-literal-oob-write
    buffer[4] = static_cast<uint8_t>(value);
}

void excluded_forms(int value, int index) {
    uint8_t buffer[4];
    // ok: cra-cpp-fixed-array-literal-oob-write
    buffer[index] = static_cast<uint8_t>(value);
    // ok: cra-cpp-fixed-array-literal-oob-write
    buffer[4U] = static_cast<uint8_t>(value);
    // ok: cra-cpp-fixed-array-literal-oob-write
    buffer[0x4] = static_cast<uint8_t>(value);
    // ok: cra-cpp-fixed-array-literal-oob-write
    buffer[-1] = static_cast<uint8_t>(value);
    // ok: cra-cpp-fixed-array-literal-oob-write
    buffer[4] += static_cast<uint8_t>(value);
    // ok: cra-cpp-fixed-array-literal-oob-write
    (void)buffer[4];
}
