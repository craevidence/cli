#include <stdlib.h>

int main(int argc, char **argv) {
    // ruleid: cra-c-system-argv
    system(argv[1]);
    // ok: cra-c-system-argv
    system("/usr/bin/id");
    return 0;
}
