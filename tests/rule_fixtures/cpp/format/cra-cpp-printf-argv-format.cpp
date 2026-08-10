#include <cstdio>

int main(int argc, char *argv[]) {
    // ruleid: cra-cpp-printf-argv-format
    printf(argv[1]);
    // ruleid: cra-cpp-printf-argv-format
    std::printf(argv[1]);
    // ok: cra-cpp-printf-argv-format
    std::printf("%s", argv[1]);
    return 0;
}
