#include <stdlib.h>

static int application_system(const char *value)
{
    return value[0];
}

int main(int argc, char **argv)
{
    system(argv[1]);
    system("printf fixed");
#define system application_system
    system(argv[1]);
#undef system
#if 0
    system(argv[1]);
#endif
    return argc;
}
