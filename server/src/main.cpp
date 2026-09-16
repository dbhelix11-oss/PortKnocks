#include <sys/stat.h>

#include <csignal>
#include <cstdio>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <vector>

#include "commands.hpp"
#include "config.hpp"
#include "firewall.hpp"
#include "log.hpp"
#include "session.hpp"
#include "sniffer.hpp"

namespace {

std::vector<uint8_t> load_secret(const std::string &path, size_t expected_len = 32) {
    struct stat st{};
    if (stat(path.c_str(), &st) != 0) {
        throw std::runtime_error("cannot stat keyfile: " + path);
    }
    if (st.st_mode & (S_IRWXG | S_IRWXO)) {
        throw std::runtime_error(path + " is readable/writable by group or other; run `chmod 600 " + path + "`");
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open keyfile: " + path);
    std::vector<uint8_t> secret((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (secret.size() != expected_len) {
        throw std::runtime_error(path + " contains " + std::to_string(secret.size()) +
                                  " bytes, expected " + std::to_string(expected_len));
    }
    return secret;
}

knockd::Sniffer *g_sniffer = nullptr;

void handle_signal(int) {
    if (g_sniffer) g_sniffer->stop();
}

} // namespace

int main(int argc, char **argv) {
    if (argc != 3 || std::string(argv[1]) != "--config") {
        std::fprintf(stderr, "usage: %s --config <path>\n", argv[0]);
        return 2;
    }

    try {
        knockd::ServerConfig cfg = knockd::load_server_config(argv[2]);

        knockd::LogLevel level;
        if (!knockd::log_level_from_string(cfg.log_level, level)) {
            std::fprintf(stderr, "invalid log_level %s (expected debug|info|warn|error)\n", cfg.log_level.c_str());
            return 2;
        }
        knockd::log_set_min_level(level);

        std::vector<uint8_t> secret = load_secret(cfg.keyfile);

        knockd::FirewallConfig fw_cfg;
        fw_cfg.target_port = cfg.target_port;
        fw_cfg.base_chain_priority = cfg.base_chain_priority;
        fw_cfg.open_duration = std::chrono::seconds(cfg.open_duration_seconds);
        knockd::Firewall firewall(fw_cfg);
        firewall.ensure_base_ruleset();

        knockd::SessionConfig sess_cfg;
        sess_cfg.secret = secret;
        sess_cfg.n_ports = cfg.n_ports;
        sess_cfg.port_low = cfg.port_low;
        sess_cfg.port_high = cfg.port_high;
        sess_cfg.time_step_seconds = cfg.time_step_seconds;
        sess_cfg.inactivity_timeout = std::chrono::seconds(cfg.inactivity_timeout_seconds);
        sess_cfg.replay_ttl = std::chrono::seconds(cfg.replay_ttl_seconds);

        knockd::SessionTracker tracker(sess_cfg, [&firewall, &cfg](const std::string &source_ip, int channel_id) {
            if (channel_id == 0) {
                LOG_INFO("knock verified from %s on channel 0, opening port %u for %ds", source_ip.c_str(),
                         cfg.target_port, cfg.open_duration_seconds);
                try {
                    firewall.open_for(source_ip);
                } catch (const std::exception &e) {
                    LOG_ERROR("firewall.open_for failed: %s", e.what());
                }
                return;
            }

            auto it = cfg.channel_commands.find(channel_id);
            if (it == cfg.channel_commands.end()) {
                LOG_WARN("knock verified from %s on channel %d, but no command is configured for it "
                         "(add [channel.%d] to knockd.conf) -- ignoring",
                         source_ip.c_str(), channel_id, channel_id);
                return;
            }

            LOG_INFO("knock verified from %s on channel %d, running %s", source_ip.c_str(), channel_id,
                      it->second.c_str());
            try {
                knockd::run_channel_command(it->second);
            } catch (const std::exception &e) {
                LOG_ERROR("channel %d command failed: %s", channel_id, e.what());
            }
        });

        knockd::SnifferConfig sniff_cfg;
        sniff_cfg.interface = cfg.interface;
        sniff_cfg.port_low = cfg.port_low;
        sniff_cfg.port_high = cfg.port_high;
        knockd::Sniffer sniffer(sniff_cfg);
        g_sniffer = &sniffer;
        std::signal(SIGINT, handle_signal);
        std::signal(SIGTERM, handle_signal);

        LOG_INFO("knockd listening on %s, ports %u-%u, log_level=%s", cfg.interface.c_str(), cfg.port_low,
                 cfg.port_high, cfg.log_level.c_str());
        sniffer.run([&tracker](const std::string &source_ip, uint16_t dest_port,
                                std::chrono::system_clock::time_point captured_at) {
            LOG_DEBUG("observed knock candidate: %s -> port %u", source_ip.c_str(), dest_port);
            tracker.on_packet(source_ip, dest_port, captured_at, std::chrono::steady_clock::now());
        });

        LOG_INFO("knockd shutting down");
        return 0;
    } catch (const std::exception &e) {
        LOG_ERROR("fatal: %s", e.what());
        return 1;
    }
}
