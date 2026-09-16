#include "config.hpp"

#include <fstream>
#include <sstream>
#include <stdexcept>
#include <unordered_map>

#include "derive.hpp"

namespace knockd {

namespace {

std::string trim(const std::string &s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

using SectionMap = std::unordered_map<std::string, std::unordered_map<std::string, std::string>>;

SectionMap parse_ini(const std::string &path) {
    std::ifstream in(path);
    if (!in) {
        throw std::runtime_error("cannot open config file: " + path);
    }
    SectionMap sections;
    std::string current_section;
    std::string line;
    while (std::getline(in, line)) {
        std::string trimmed = trim(line);
        if (trimmed.empty() || trimmed[0] == '#' || trimmed[0] == ';') continue;
        if (trimmed.front() == '[' && trimmed.back() == ']') {
            current_section = trim(trimmed.substr(1, trimmed.size() - 2));
            continue;
        }
        auto eq = trimmed.find('=');
        if (eq == std::string::npos) continue;
        std::string key = trim(trimmed.substr(0, eq));
        std::string value = trim(trimmed.substr(eq + 1));
        sections[current_section][key] = value;
    }
    return sections;
}

std::string require(const SectionMap &sections, const std::string &section, const std::string &key) {
    auto sit = sections.find(section);
    if (sit == sections.end()) throw std::runtime_error("missing config section: [" + section + "]");
    auto kit = sit->second.find(key);
    if (kit == sit->second.end()) throw std::runtime_error("missing config key: " + section + "." + key);
    return kit->second;
}

int get_int(const SectionMap &sections, const std::string &section, const std::string &key, int fallback) {
    auto sit = sections.find(section);
    if (sit == sections.end()) return fallback;
    auto kit = sit->second.find(key);
    if (kit == sit->second.end()) return fallback;
    return std::stoi(kit->second);
}

std::string get_string(const SectionMap &sections, const std::string &section, const std::string &key,
                        const std::string &fallback) {
    auto sit = sections.find(section);
    if (sit == sections.end()) return fallback;
    auto kit = sit->second.find(key);
    if (kit == sit->second.end()) return fallback;
    return kit->second;
}

std::map<int, std::string> parse_channel_commands(const SectionMap &sections) {
    std::map<int, std::string> commands;
    for (int channel = 1; channel < kNumChannels; ++channel) {
        auto sit = sections.find("channel." + std::to_string(channel));
        if (sit == sections.end()) continue;
        auto kit = sit->second.find("command");
        if (kit == sit->second.end()) continue;
        commands[channel] = kit->second;
    }
    return commands;
}

} // namespace

ServerConfig load_server_config(const std::string &path) {
    auto sections = parse_ini(path);

    ServerConfig cfg;
    cfg.keyfile = require(sections, "knock", "keyfile");
    cfg.time_step_seconds = get_int(sections, "knock", "time_step", 30);
    cfg.n_ports = get_int(sections, "knock", "n_ports", 6);
    cfg.port_low = static_cast<uint16_t>(get_int(sections, "knock", "port_low", 20000));
    cfg.port_high = static_cast<uint16_t>(get_int(sections, "knock", "port_high", 60000));
    cfg.inactivity_timeout_seconds = get_int(sections, "knock", "inactivity_timeout", 5);
    cfg.replay_ttl_seconds = get_int(sections, "knock", "replay_ttl", 90);

    cfg.interface = require(sections, "server", "interface");
    cfg.target_port = static_cast<uint16_t>(get_int(sections, "server", "target_port", 22));
    cfg.open_duration_seconds = get_int(sections, "server", "open_duration", 30);
    cfg.base_chain_priority = get_int(sections, "server", "base_chain_priority", -10);
    cfg.log_level = get_string(sections, "server", "log_level", "info");

    cfg.channel_commands = parse_channel_commands(sections);

    return cfg;
}

} // namespace knockd
