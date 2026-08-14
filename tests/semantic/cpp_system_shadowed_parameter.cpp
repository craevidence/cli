#include <cstdlib>

int main(int argc, char **argv)
{
    auto run = [](char **argv) { return std::system(argv[1]); };
    return argc + run(argv);
}
