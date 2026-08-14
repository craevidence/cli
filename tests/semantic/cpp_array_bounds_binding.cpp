#include <cstdint>

void direct_assignment(int value) {
    uint8_t buffer[4];
    buffer[3] = static_cast<uint8_t>(value);
    buffer[4] = static_cast<uint8_t>(value);
}

void macro_redirect(int value) {
    uint8_t buffer[4];
    uint8_t other[20];
#define buffer other
    buffer[4] = static_cast<uint8_t>(value);
#undef buffer
    buffer[4] = static_cast<uint8_t>(value);
}

#if 0
void inactive(int value) {
    uint8_t buffer[4];
    buffer[4] = static_cast<uint8_t>(value);
}
#endif
