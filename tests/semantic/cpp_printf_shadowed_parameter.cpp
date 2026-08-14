#include <cstdio>

int main(int argc, char **argv)
{
    auto render = [](char **argv) { return std::printf(argv[1]); };
    return argc + render(argv);
}
