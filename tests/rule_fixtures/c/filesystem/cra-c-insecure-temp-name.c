#include <stdio.h>
#include <stdlib.h>

void bad(void) {
    char name[L_tmpnam];
    // ruleid: cra-c-insecure-temp-name
    tmpnam(name);
}

void bad_tempnam(void) {
    // ruleid: cra-c-insecure-temp-name
    char *name = tempnam("/tmp", "app-");
    free(name);
}

void good(void) {
    char template[] = "/tmp/app-XXXXXX";
    // ok: cra-c-insecure-temp-name
    int descriptor = mkstemp(template);
    (void)descriptor;
}
