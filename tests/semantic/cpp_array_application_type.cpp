struct Element {
    Element &operator=(int) { return *this; }
};
using uint8_t = Element;

void application_element(int value) {
    uint8_t buffer[4];
    buffer[4] = value;
}
