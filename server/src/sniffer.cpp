#include "sniffer.hpp"

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap/pcap.h>

#include <cstring>
#include <sstream>
#include <stdexcept>

namespace knockd {

namespace {

struct CallbackContext {
    const KnockCallback *on_knock;
};

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *bytes) {
    auto *ctx = reinterpret_cast<CallbackContext *>(user);

    if (header->caplen < sizeof(struct ether_header)) return;
    const auto *eth = reinterpret_cast<const struct ether_header *>(bytes);
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return;

    const u_char *ip_start = bytes + sizeof(struct ether_header);
    if (header->caplen < sizeof(struct ether_header) + sizeof(struct ip)) return;
    const auto *iph = reinterpret_cast<const struct ip *>(ip_start);
    if (iph->ip_p != IPPROTO_TCP) return;

    size_t ip_header_len = static_cast<size_t>(iph->ip_hl) * 4;
    const u_char *tcp_start = ip_start + ip_header_len;
    if (bytes + header->caplen < tcp_start + sizeof(struct tcphdr)) return;
    const auto *tcph = reinterpret_cast<const struct tcphdr *>(tcp_start);

    // BPF filter already restricts to SYN-only, but double-check defensively.
    if (!(tcph->th_flags & TH_SYN) || (tcph->th_flags & TH_ACK)) return;

    char src_buf[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &iph->ip_src, src_buf, sizeof(src_buf))) return;

    uint16_t dest_port = ntohs(tcph->th_dport);

    auto captured_at = std::chrono::system_clock::time_point(
        std::chrono::duration_cast<std::chrono::system_clock::duration>(
            std::chrono::seconds(header->ts.tv_sec) + std::chrono::microseconds(header->ts.tv_usec)));

    (*ctx->on_knock)(std::string(src_buf), dest_port, captured_at);
}

} // namespace

Sniffer::Sniffer(SnifferConfig config) : config_(std::move(config)) {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    handle_ = pcap_open_live(config_.interface.c_str(), 65535, /*promisc=*/0, /*timeout_ms=*/100, errbuf);
    if (!handle_) {
        throw std::runtime_error(std::string("pcap_open_live failed: ") + errbuf);
    }

    if (pcap_datalink(handle_) != DLT_EN10MB) {
        pcap_close(handle_);
        handle_ = nullptr;
        throw std::runtime_error("unsupported datalink type; only Ethernet-framed interfaces (DLT_EN10MB) are supported");
    }

    std::ostringstream filter;
    filter << "tcp and tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn"
           << " and dst portrange " << config_.port_low << "-" << config_.port_high;

    struct bpf_program prog;
    if (pcap_compile(handle_, &prog, filter.str().c_str(), /*optimize=*/1, PCAP_NETMASK_UNKNOWN) != 0) {
        std::string err = pcap_geterr(handle_);
        pcap_close(handle_);
        handle_ = nullptr;
        throw std::runtime_error("pcap_compile failed: " + err);
    }
    int set_rc = pcap_setfilter(handle_, &prog);
    pcap_freecode(&prog);
    if (set_rc != 0) {
        std::string err = pcap_geterr(handle_);
        pcap_close(handle_);
        handle_ = nullptr;
        throw std::runtime_error("pcap_setfilter failed: " + err);
    }
}

Sniffer::~Sniffer() {
    if (handle_) {
        pcap_close(handle_);
    }
}

void Sniffer::run(const KnockCallback &on_knock) {
    CallbackContext ctx{&on_knock};
    // pcap_loop returns -1 on error, -2 if pcap_breakloop() was called, or 0
    // if the packet count limit is reached (we pass -1, i.e. no limit).
    pcap_loop(handle_, -1, packet_handler, reinterpret_cast<u_char *>(&ctx));
}

void Sniffer::stop() {
    if (handle_) {
        pcap_breakloop(handle_);
    }
}

} // namespace knockd
