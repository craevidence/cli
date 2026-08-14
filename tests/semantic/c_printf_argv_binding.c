#include <stdio.h>

static int application_printf(const char *value)
{
    return value[0];
}

int main(int argc, char **argv)
{
    printf(argv[1]);
    printf("%s", argv[1]);
#define printf application_printf
    printf(argv[1]);
#undef printf
#if 0
    printf(argv[1]);
#endif
    return argc;
}
