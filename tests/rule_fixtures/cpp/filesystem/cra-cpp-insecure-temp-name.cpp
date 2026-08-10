#include <cstdio>
#include <cstdlib>

void bad() {
    char name[L_tmpnam];
    // ruleid: cra-cpp-insecure-temp-name
    std::tmpnam(name);
}

void bad_tempnam() {
    // ruleid: cra-cpp-insecure-temp-name
    char *name = tempnam("/tmp", "app-");
    std::free(name);
}

void good() {
    char pattern[] = "/tmp/app-XXXXXX";
    // ok: cra-cpp-insecure-temp-name
    int descriptor = mkstemp(pattern);
    (void)descriptor;
}
