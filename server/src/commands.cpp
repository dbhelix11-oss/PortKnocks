#include "commands.hpp"

#include "proc.hpp"

namespace knockd {

void run_channel_command(const std::string &command_path) {
    exec_and_wait(command_path, {});
}

} // namespace knockd
