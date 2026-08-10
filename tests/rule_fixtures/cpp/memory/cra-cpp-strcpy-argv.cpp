#include <cstdio>
#include <cstring>

int main(int argc, char *argv[]) {
    char destination[32];
    // ruleid: cra-cpp-strcpy-argv
    std::strcpy(destination, argv[1]);
    // ok: cra-cpp-strcpy-argv
    std::snprintf(destination, sizeof(destination), "%s", argv[1]);
    return 0;
}
