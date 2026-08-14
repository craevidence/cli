#include <stdlib.h>

static int run(char **argv)
{
    return system(argv[1]);
}

int main(int argc, char **argv)
{
    return argc + run(argv);
}
