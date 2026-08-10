#include <cstdlib>

int main(int argc, char *argv[]) {
    // ruleid: cra-cpp-system-argv
    std::system(argv[1]);
    // ok: cra-cpp-system-argv
    std::system("/usr/bin/id");
    return 0;
}
