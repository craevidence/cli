#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char destination[32];
    // ruleid: cra-c-strcpy-argv
    strcpy(destination, argv[1]);
    // ok: cra-c-strcpy-argv
    snprintf(destination, sizeof(destination), "%s", argv[1]);
    return 0;
}
