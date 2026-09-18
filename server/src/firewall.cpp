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
    chain_spec << "{ type filter hook input priority " << config_.base_chain_priority << " ; policy "
               << (config_.default_deny ? "drop" : "accept") << " ; }";
    run_nft({"add", "chain", config_.family, config_.table, config_.chain, chain_spec.str()});

    // Every rule below lives in THIS one chain, in this order. That is
    // required, not stylistic: nftables/netfilter evaluate separate base
    // chains hooked at the same point (e.g. "input") independently, and an
    // `accept` verdict in one chain does NOT override a `drop`/`reject` in
    // a different, later-evaluated chain -- only a terminal drop/reject
    // anywhere is truly final. So knockd cannot rely on an existing,
    // separately-managed deny (or allow) rule living in a different chain;
    // it must own the complete decision itself, as ordered rules in one
    // chain.

    // First, always: let already-open connections keep flowing regardless
    // of the timed allow-set's expiry. Conntrack tracks state per the full
    // 5-tuple, so this does not also admit a brand-new connection from the
    // same source once its set entry has expired -- only traffic that is
    // already part of a tracked connection matches "established".
    run_nft({"add", "rule", config_.family, config_.table, config_.chain,
             "ct state established,related accept"});

    if (config_.default_deny) {
        // Ports that are always reachable regardless of any knock (e.g. a
        // decoy port you want open no matter what).
        for (uint16_t port : config_.always_allow_ports) {
            std::ostringstream allow_rule;
            allow_rule << "tcp dport " << port << " accept";
            run_nft({"add", "rule", config_.family, config_.table, config_.chain, allow_rule.str()});
        }
    }

    // The knock-gated port: accept for source IPs in the timed set. Using
    // `drop` rather than `reject` for the target_port fallback (below, in
    // non-default-deny mode) keeps the port silent to unauthenticated
    // probes, matching the point of port-knocking in the first place.
    std::ostringstream accept_rule;
    accept_rule << "ip saddr @" << config_.set_name << " tcp dport " << config_.target_port << " accept";
    run_nft({"add", "rule", config_.family, config_.table, config_.chain, accept_rule.str()});

    if (!config_.default_deny) {
        // In this mode knockd only ever touches target_port -- everything
        // else on the host is left alone. In default_deny mode this
        // explicit rule is unnecessary: the chain's own `drop` policy
        // already covers target_port (and every other port) once nothing
        // above has matched.
        //
        // "add rule" without a handle is not idempotent, so this may run
        // more than once across restarts and create duplicate (harmless,
        // identical) rules; operators restarting knockd repeatedly should
        // periodically flush and recreate the chain, documented in
        // README.md.
        std::ostringstream deny_rule;
        deny_rule << "tcp dport " << config_.target_port << " drop";
        run_nft({"add", "rule", config_.family, config_.table, config_.chain, deny_rule.str()});
    }
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
