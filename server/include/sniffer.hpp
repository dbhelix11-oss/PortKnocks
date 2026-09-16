#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <string>

// Forward-declared to keep libpcap's headers out of anything that just needs
// to construct/own a Sniffer (only sniffer.cpp includes <pcap/pcap.h>).
typedef struct pcap pcap_t;

namespace knockd {

struct SnifferConfig {
    std::string interface; // e.g. "lo", "eth0"
    uint16_t port_low = 20000;
    uint16_t port_high = 60000;
};

using KnockCallback = std::function<void(const std::string &source_ip, uint16_t dest_port,
                                          std::chrono::system_clock::time_point captured_at)>;

class Sniffer {
public:
    explicit Sniffer(SnifferConfig config);
    ~Sniffer();

    Sniffer(const Sniffer &) = delete;
    Sniffer &operator=(const Sniffer &) = delete;

    // Blocks the calling thread, invoking on_knock for every TCP SYN packet
    // destined to the configured port range. Requires CAP_NET_RAW (typically
    // root, or `setcap cap_net_raw+ep` on the binary). Returns when stop() is
    // called from another thread.
    void run(const KnockCallback &on_knock);

    void stop();

private:
    SnifferConfig config_;
    pcap_t *handle_ = nullptr;
};

} // namespace knockd
