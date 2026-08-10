#include <cstdlib>
#include <spawn.h>

const char *configured_command() {
    return std::getenv("APP_COMMAND");
}

void bad_across_helper() {
    const char *command = configured_command();
    // ruleid: cra-cpp-system-getenv-taint
    std::system(command);
}

void bad() {
    const char *command = std::getenv("APP_COMMAND");
    // ruleid: cra-cpp-system-getenv-taint
    std::system(command);
}

void good() {
    char *arguments[] = {const_cast<char *>("id"), nullptr};
    // ok: cra-cpp-system-getenv-taint
    posix_spawn(nullptr, "/usr/bin/id", nullptr, nullptr, arguments, nullptr);
}
