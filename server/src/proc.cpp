#include "proc.hpp"

#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <sstream>
#include <stdexcept>

namespace knockd {

void exec_and_wait(const std::string &program, const std::vector<std::string> &args) {
    std::vector<char *> argv;
    argv.push_back(const_cast<char *>(program.c_str()));
    for (const auto &a : args) {
        argv.push_back(const_cast<char *>(a.c_str()));
    }
    argv.push_back(nullptr);

    pid_t pid = fork();
    if (pid < 0) {
        throw std::runtime_error("fork() failed");
    }
    if (pid == 0) {
        // Child: exec directly (execvp does its own PATH search, no shell
        // is invoked).
        execvp(program.c_str(), argv.data());
        std::perror(("execvp(" + program + ")").c_str());
        _exit(127);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        throw std::runtime_error("waitpid() failed");
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        std::ostringstream cmd;
        cmd << program;
        for (const auto &a : args) cmd << ' ' << a;
        throw std::runtime_error("command failed: " + cmd.str());
    }
}

} // namespace knockd
