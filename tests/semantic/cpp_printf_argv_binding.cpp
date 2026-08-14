#include <cstdio>

static int application_printf(const char *value)
{
    return value[0];
}

int main(int argc, char **argv)
{
    printf(argv[1]);
    std::printf(argv[1]);
    std::printf("%s", argv[1]);
#define printf application_printf
    printf(argv[1]);
#undef printf
#if 0
    std::printf(argv[1]);
#endif
    return argc;
}
