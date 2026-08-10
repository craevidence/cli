#include <stdlib.h>
#include <unistd.h>

char *configured_command(void) {
    return getenv("APP_COMMAND");
}

void bad_across_helper(void) {
    char *command = configured_command();
    // ruleid: cra-c-system-getenv-taint
    system(command);
}

void bad(void) {
    char *command = getenv("APP_COMMAND");
    // ruleid: cra-c-system-getenv-taint
    system(command);
}

void good(void) {
    char *argument = getenv("APP_ARGUMENT");
    // ok: cra-c-system-getenv-taint
    execl("/usr/bin/lookup", "lookup", argument, (char *)0);
}

/* Bad: the environment value is copied into a buffer before the sink */
void badEnvThroughBuffer(void)
{
    char command[256];
    snprintf(command, sizeof(command), "ls %s", getenv("TARGET_DIR"));
    /* ruleid: cra-c-system-getenv-taint */
    system(command);
}
