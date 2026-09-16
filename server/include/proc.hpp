#pragma once

#include <string>
#include <vector>

namespace knockd {

// Forks and execvp's `program` (PATH-searched, like execvp) with `args` as
// its remaining argv, waits for it to exit, and throws std::runtime_error
// if it can't be started or exits nonzero. No shell is ever invoked, so
// there is no shell-injection risk from any argument string -- each
// element of `args` reaches the child as a single argv entry, exactly as
// written, regardless of its contents.
void exec_and_wait(const std::string &program, const std::vector<std::string> &args);

} // namespace knockd
