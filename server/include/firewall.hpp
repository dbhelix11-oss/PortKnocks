#pragma once

#include <chrono>
#include <cstdint>
#include <map>
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
// is what stops target_ports' timer from severing an already-open session
// out from under you. The same holds for any channel_port_groups port.
//
// Two modes, chosen by `default_deny`:
//  - default_deny = false (default): chain policy `accept`; the only
//    thing knockd's chain actively enforces is target_ports and any
//    channel_port_groups ports (each gets an accept-if-in-set rule
//    followed by an explicit drop). Every other port on the host is
//    untouched by this chain.
//  - default_deny = true: chain policy `drop`; knockd's chain becomes the
//    default-deny authority for the ENTIRE host, not just those ports.
//    Ports in `always_allow_ports` are always reachable (e.g. a decoy
//    SSH port you want open regardless of any knock); target_ports and
//    channel_port_groups ports are still knock-gated; everything else is
//    dropped by the chain's own policy.
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
    // All opened together, by the same set, for a channel-0 knock -- one
    // source IP entry admits traffic to every port in this list.
    std::vector<uint16_t> target_ports = {22};
    int base_chain_priority = -10;
    std::chrono::seconds open_duration{30};

    bool default_deny = false;
    std::vector<uint16_t> always_allow_ports; // only meaningful if default_deny

    // Extra port groups opened by channels 1-10 configured with
    // `open_port` (see ServerConfig::ChannelAction). Each entry is one
    // channel's own list of ports, opened together via that channel's own
    // timed set -- keyed by channel_id so open_port_for() can find it.
    std::map<int, std::vector<uint16_t>> channel_port_groups;
};

class Firewall {
public:
    explicit Firewall(FirewallConfig config);

    // Idempotent: creates the table/set/chain/rule if missing. Call once at
    // startup. Requires CAP_NET_ADMIN (typically root).
    void ensure_base_ruleset() const;

    // Adds source_ip to the primary timed allow-set, opening every port in
    // target_ports for it. Throws std::runtime_error if source_ip fails
    // basic IPv4 validation or the nft invocation fails.
    void open_for(const std::string &source_ip) const;

    // Same, for a channel configured with `open_port` -- opens every port
    // in that channel's own list. Throws std::runtime_error if channel_id
    // isn't one of channel_port_groups (a config/dispatch mismatch) or if
    // source_ip/the nft invocation fails.
    void open_port_for(const std::string &source_ip, int channel_id) const;

private:
    void run_nft(const std::vector<std::string> &args) const;
    void add_to_set(const std::string &source_ip, const std::string &set_name) const;
    // Creates set_name (if missing) and, for each port in ports, an
    // accept-if-in-set rule plus (unless default_deny) an explicit drop --
    // the same treatment target_ports and every channel_port_groups entry
    // get in ensure_base_ruleset().
    void setup_port_group(const std::string &set_name, const std::vector<uint16_t> &ports) const;

    FirewallConfig config_;
};

} // namespace knockd
