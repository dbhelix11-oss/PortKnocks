#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace knockd {

// nftables integration. Uses a dynamic set with `flags timeout` rather than
// a raw per-rule timeout (nftables timeouts are a property of set elements,
// not of ordinary filter rules) -- the kernel expires an element on its own
// once open_duration elapses.
//
// knockd's chain owns the COMPLETE policy for target_port: an accept rule
// for source IPs in the timed set, followed by an unconditional drop for
// everything else. It deliberately does not rely on a separately-managed
// deny rule living elsewhere: nftables evaluates independent base chains
// hooked at the same point (e.g. "input") in priority order, and an
// `accept` verdict in one chain does NOT suppress a `drop`/`reject` in a
// different, later-evaluated chain -- only a terminal drop/reject anywhere
// is final. If target_port is also referenced by another firewall chain on
// this host, reconcile that separately; knockd's own chain cannot override
// it just by running at an earlier priority.
struct FirewallConfig {
    std::string family = "inet";
    std::string table = "knockd";
    std::string chain = "knockd_input";
    std::string set_name = "knockd_allowed";
    uint16_t target_port = 22;
    int base_chain_priority = -10;
    std::chrono::seconds open_duration{30};
};

class Firewall {
public:
    explicit Firewall(FirewallConfig config);

    // Idempotent: creates the table/set/chain/rule if missing. Call once at
    // startup. Requires CAP_NET_ADMIN (typically root).
    void ensure_base_ruleset() const;

    // Adds source_ip to the timed allow-set. Throws std::runtime_error if
    // source_ip fails basic IPv4 validation or the nft invocation fails.
    void open_for(const std::string &source_ip) const;

private:
    void run_nft(const std::vector<std::string> &args) const;

    FirewallConfig config_;
};

} // namespace knockd
