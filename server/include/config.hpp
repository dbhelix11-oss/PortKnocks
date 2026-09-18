#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace knockd {

// Minimal `[section]\nkey = value` reader -- deliberately hand-rolled rather
// than pulling in an INI library for a handful of scalar fields.
struct ServerConfig {
    std::string keyfile;
    int time_step_seconds = 30;
    int n_ports = 6;
    uint16_t port_low = 20000;
    uint16_t port_high = 60000;
    int inactivity_timeout_seconds = 5;
    int replay_ttl_seconds = 90;

    std::string interface;
    uint16_t target_port = 22;
    int open_duration_seconds = 30;
    int base_chain_priority = -10;

    // See firewall.hpp's FirewallConfig comment for what these mean --
    // default_deny=false (the default) preserves knockd's original
    // narrow behavior (only ever touches target_port); default_deny=true
    // makes knockd's chain the default-deny authority for the whole
    // host, with always_allow_ports reachable regardless of any knock.
    bool default_deny = false;
    std::vector<uint16_t> always_allow_ports;

    std::string log_level = "info"; // debug | info | warn | error

    // Channel 0 is not configured here -- it's hardcoded to opening
    // target_port (see main.cpp's dispatch). channel_commands maps
    // channel_id (1..10) -> the command path from that channel's
    // [channel.N] section; a channel with no entry here that still fires
    // is logged and otherwise ignored.
    std::map<int, std::string> channel_commands;
};

ServerConfig load_server_config(const std::string &path);

} // namespace knockd
