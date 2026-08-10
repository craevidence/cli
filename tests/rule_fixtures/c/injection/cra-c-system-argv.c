#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    // ruleid: cra-c-system-argv
    system(argv[1]);

    // ok: cra-c-system-argv
    execl("/usr/bin/id", "id", (char *)0);
    return 0;
}
