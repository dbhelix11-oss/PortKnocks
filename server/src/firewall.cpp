#include "firewall.hpp"

#include <arpa/inet.h>

#include <sstream>
#include <stdexcept>

#include "proc.hpp"

namespace knockd {

namespace {

bool looks_like_ipv4(const std::string &s) {
    struct in_addr addr;
    return inet_pton(AF_INET, s.c_str(), &addr) == 1;
}

} // namespace

Firewall::Firewall(FirewallConfig config) : config_(std::move(config)) {}

void Firewall::run_nft(const std::vector<std::string> &args) const {
    exec_and_wait("nft", args);
}

void Firewall::ensure_base_ruleset() const {
    run_nft({"add", "table", config_.family, config_.table});

    run_nft({"add", "set", config_.family, config_.table, config_.set_name,
             "{", "type", "ipv4_addr;", "flags", "timeout;", "}"});

    std::ostringstream chain_spec;
    chain_spec << "{ type filter hook input priority " << config_.base_chain_priority << " ; policy accept ; }";
    run_nft({"add", "chain", config_.family, config_.table, config_.chain, chain_spec.str()});

    // Both the allow-exception and the fallback deny live in THIS chain, in
    // this order. That is required, not stylistic: nftables/netfilter
    // evaluate separate base chains hooked at the same point (e.g. "input")
    // independently, and an `accept` verdict in one chain does NOT override
    // a `drop`/`reject` in a different, later-evaluated chain -- only a
    // terminal drop/reject anywhere is truly final. So knockd cannot rely on
    // an existing, separately-managed deny rule elsewhere and simply "jump
    // the queue" with an early accept; it must own the complete decision
    // (allow-if-in-set, else deny) for target_port itself, as two ordered
    // rules in one chain. Using `drop` rather than `reject` for the
    // fallback keeps the target port silent to unauthenticated probes,
    // matching the point of port-knocking in the first place.
    std::ostringstream accept_rule;
    accept_rule << "ip saddr @" << config_.set_name << " tcp dport " << config_.target_port << " accept";
    std::ostringstream deny_rule;
    deny_rule << "tcp dport " << config_.target_port << " drop";

    // "add rule" without a handle is not idempotent, so this may be run more
    // than once across restarts and create duplicate (harmless, identical)
    // rules; operators restarting knockd repeatedly should periodically
    // flush and recreate the chain, documented in README.md.
    run_nft({"add", "rule", config_.family, config_.table, config_.chain, accept_rule.str()});
    run_nft({"add", "rule", config_.family, config_.table, config_.chain, deny_rule.str()});
}

void Firewall::open_for(const std::string &source_ip) const {
    if (!looks_like_ipv4(source_ip)) {
        throw std::runtime_error("refusing to open firewall for non-IPv4 address: " + source_ip);
    }
    std::ostringstream element;
    element << "{ " << source_ip << " timeout " << config_.open_duration.count() << "s }";
    run_nft({"add", "element", config_.family, config_.table, config_.set_name, element.str()});
}

} // namespace knockd
