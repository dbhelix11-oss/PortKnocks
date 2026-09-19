#include "config.hpp"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <stdexcept>
#include <string>

using namespace knockd;

namespace {

int failures = 0;

void check(bool cond, const char *msg) {
    if (!cond) {
        std::fprintf(stderr, "FAIL: %s\n", msg);
        ++failures;
    }
}

// Each test gets its own temp file so parallel/repeated runs can't collide.
std::string write_temp_config(const std::string &contents, const char *suffix) {
    std::string path = "/tmp/knockd_test_config_" + std::string(suffix) + ".conf";
    std::ofstream out(path);
    out << contents;
    out.close();
    return path;
}

const char *kBase = R"(
[knock]
keyfile = /tmp/does-not-need-to-exist.key

[server]
interface = lo
)";

} // namespace

int main() {
    // --- target_port defaults to {22} when unset ---
    {
        std::string path = write_temp_config(kBase, "default_target");
        ServerConfig cfg = load_server_config(path);
        check(cfg.target_ports.size() == 1 && cfg.target_ports[0] == 22,
              "target_port should default to {22}");
    }

    // --- target_port accepts a comma-separated list ---
    {
        std::string contents = std::string(kBase) + "target_port = 22, 80,443\n";
        std::string path = write_temp_config(contents, "comma_target");
        ServerConfig cfg = load_server_config(path);
        check(cfg.target_ports.size() == 3 && cfg.target_ports[0] == 22 && cfg.target_ports[1] == 80 &&
                  cfg.target_ports[2] == 443,
              "target_port should parse a comma-separated list");
    }

    // --- target_port accepts a whitespace-separated list ---
    {
        std::string contents = std::string(kBase) + "target_port = 22 80 443\n";
        std::string path = write_temp_config(contents, "space_target");
        ServerConfig cfg = load_server_config(path);
        check(cfg.target_ports.size() == 3 && cfg.target_ports[1] == 80,
              "target_port should parse a whitespace-separated list");
    }

    // --- a channel with `command` parses to a command action ---
    {
        std::string contents = std::string(kBase) + "\n[channel.1]\ncommand = /usr/bin/true\n";
        std::string path = write_temp_config(contents, "channel_command");
        ServerConfig cfg = load_server_config(path);
        auto it = cfg.channel_actions.find(1);
        check(it != cfg.channel_actions.end(), "channel 1 should have a parsed action");
        if (it != cfg.channel_actions.end()) {
            check(it->second.command == "/usr/bin/true", "channel 1's command should be parsed");
            check(it->second.open_ports.empty(), "channel 1's open_ports should be empty when command is set");
        }
    }

    // --- a channel with `open_port` (single) parses to an open_ports action ---
    {
        std::string contents = std::string(kBase) + "\n[channel.2]\nopen_port = 8080\n";
        std::string path = write_temp_config(contents, "channel_open_port_single");
        ServerConfig cfg = load_server_config(path);
        auto it = cfg.channel_actions.find(2);
        check(it != cfg.channel_actions.end(), "channel 2 should have a parsed action");
        if (it != cfg.channel_actions.end()) {
            check(it->second.command.empty(), "channel 2's command should be empty when open_port is set");
            check(it->second.open_ports.size() == 1 && it->second.open_ports[0] == 8080,
                  "channel 2's open_ports should contain 8080");
        }
    }

    // --- a channel with `open_port` (comma list) parses multiple ports ---
    {
        std::string contents = std::string(kBase) + "\n[channel.3]\nopen_port = 8080, 8443\n";
        std::string path = write_temp_config(contents, "channel_open_port_multi");
        ServerConfig cfg = load_server_config(path);
        auto it = cfg.channel_actions.find(3);
        check(it != cfg.channel_actions.end() && it->second.open_ports.size() == 2 &&
                  it->second.open_ports[0] == 8080 && it->second.open_ports[1] == 8443,
              "channel 3's open_ports should contain both 8080 and 8443");
    }

    // --- a channel with neither key is simply absent, not an error ---
    {
        std::string contents = std::string(kBase) + "\n[channel.4]\n";
        std::string path = write_temp_config(contents, "channel_neither");
        ServerConfig cfg = load_server_config(path);
        check(cfg.channel_actions.find(4) == cfg.channel_actions.end(),
              "channel 4 with no command/open_port key should not appear in channel_actions");
    }

    // --- a channel with BOTH keys is a config error ---
    {
        std::string contents = std::string(kBase) + "\n[channel.5]\ncommand = /usr/bin/true\nopen_port = 8080\n";
        std::string path = write_temp_config(contents, "channel_both");
        bool threw = false;
        try {
            load_server_config(path);
        } catch (const std::runtime_error &) {
            threw = true;
        }
        check(threw, "a channel setting both command and open_port should throw");
    }

    if (failures == 0) {
        std::printf("all config tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d failure(s)\n", failures);
    return 1;
}
