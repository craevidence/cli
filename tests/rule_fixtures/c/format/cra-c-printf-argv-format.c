#include <stdio.h>

int main(int argc, char *argv[]) {
    // ruleid: cra-c-printf-argv-format
    printf(argv[1]);
    // ok: cra-c-printf-argv-format
    printf("%s", argv[1]);
    return 0;
}
