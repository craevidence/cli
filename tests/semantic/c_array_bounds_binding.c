#include <stdint.h>

void direct_assignment(int value) {
    uint8_t buffer[4];
    buffer[3] = (uint8_t)value;
    buffer[4] = (uint8_t)value;
}

void macro_redirect(int value) {
    uint8_t buffer[4];
    uint8_t other[20];
#define buffer other
    buffer[4] = (uint8_t)value;
#undef buffer
    buffer[4] = (uint8_t)value;
}
