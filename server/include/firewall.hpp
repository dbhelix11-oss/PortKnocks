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
// knockd's chain owns a COMPLETE policy, not just a knock-gated exception,
// and always starts with `ct state established,related accept`: once a
// connection is up, its packets keep flowing regardless of the timed
// set's expiry (conntrack tracks state per the full 5-tuple, so this does
// not also admit a *new* connection from the same source once its set
// entry has expired -- only already-established traffic is exempt). This
// is what stops target_port's timer from severing an already-open session
// out from under you.
//
// Two modes, chosen by `default_deny`:
//  - default_deny = false (default): chain policy `accept`; the only
//    thing knockd's chain actively enforces is target_port itself (an
//    accept-if-in-set rule followed by an explicit drop for target_port).
//    Every other port on the host is untouched by this chain.
//  - default_deny = true: chain policy `drop`; knockd's chain becomes the
//    default-deny authority for the ENTIRE host, not just target_port.
//    Ports in `always_allow_ports` are always reachable (e.g. a decoy
//    SSH port you want open regardless of any knock); target_port is
//    still knock-gated; everything else is dropped by the chain's own
//    policy.
//
// Either way, it deliberately does not rely on a separately-managed deny
// rule living in a DIFFERENT chain: nftables evaluates independent base
// chains hooked at the same point (e.g. "input") in priority order, and
// an `accept` verdict in one chain does NOT suppress a `drop`/`reject` in
// a different, later-evaluated chain -- only a terminal drop/reject
// anywhere is final. So "deny everything except my decoy port" can't be
// built as a second, separate chain alongside knockd's -- it has to live
// in knockd's own chain (via `default_deny` + `always_allow_ports`), or
// it will not reliably override knockd's own accept decisions.
struct FirewallConfig {
    std::string family = "inet";
    std::string table = "knockd";
    std::string chain = "knockd_input";
    std::string set_name = "knockd_allowed";
    uint16_t target_port = 22;
    int base_chain_priority = -10;
    std::chrono::seconds open_duration{30};

    bool default_deny = false;
    std::vector<uint16_t> always_allow_ports; // only meaningful if default_deny
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
