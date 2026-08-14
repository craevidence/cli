#include <cstdlib>

static int application_system(const char *value)
{
    return value[0];
}

int main(int argc, char **argv)
{
    system(argv[1]);
    std::system(argv[1]);
    std::system("printf fixed");
#define system application_system
    system(argv[1]);
#undef system
#if 0
    std::system(argv[1]);
#endif
    return argc;
}
