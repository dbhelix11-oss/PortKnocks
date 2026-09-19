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
    // Ports a channel-0 knock opens, all together, for the knocking
    // source IP. Config key is still singular (`target_port`) for
    // backward compatibility with existing knockd.conf files -- its
    // value now accepts a comma- and/or whitespace-separated list.
    // Defaults to {22} if unset.
    std::vector<uint16_t> target_ports = {22};
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
    // target_ports (see main.cpp's dispatch). Channels 1-10 each run
    // exactly one of two mutually exclusive actions, set in that
    // channel's [channel.N] section: `command = <path>` (run it, no
    // args) or `open_port = <N[, N...]>` (open those ports, together,
    // for the knocking source IP, the same way channel 0 opens
    // target_ports). A channel with no [channel.N] section, or one with
    // neither key, is logged and otherwise ignored when it fires;
    // load_server_config throws if a section sets both keys.
    struct ChannelAction {
        std::string command;             // empty if open_ports is used
        std::vector<uint16_t> open_ports; // empty if command is used
    };
    std::map<int, ChannelAction> channel_actions;
};

ServerConfig load_server_config(const std::string &path);

} // namespace knockd
