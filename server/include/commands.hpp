#pragma once

#include <string>

namespace knockd {

// Runs a channel's configured command with no arguments (fork+execve via
// exec_and_wait -- never a shell). Throws std::runtime_error if the
// command can't be started or exits nonzero; callers should catch and log
// rather than let a misbehaving channel command take down the daemon.
void run_channel_command(const std::string &command_path);

} // namespace knockd
