# PortKnocks

A custom port-knocking authorization system: the sequence of TCP ports a
client must "knock" on is derived from a shared secret and the current time
window (TOTP-style — the same rolling-code idea as a 30-second one-time
password), rather than being a static, easily-replayed sequence. Design
notes and the exact derivation algorithm live in `spec/derivation.md`.

- `client/` — Python client that computes the sequence and sends the knocks.
- `server/` — C++ daemon that passively sniffs for the sequence (via
  libpcap — it never opens a listening socket on the knock ports) and, on a
  verified match, opens the target port for that source IP via an nftables
  rule with kernel-enforced expiry.
- `spec/` — the language-agnostic derivation spec and cross-language test
  vectors both implementations are checked against.

## How it works

1. Generate a 32-byte shared secret once and copy it to both machines:
   ```
   openssl rand -out secret.key 32
   chmod 600 secret.key
   ```
2. Client and server config files (`client/knock.conf.example`,
   `server/knockd.conf.example`) must agree on `time_step`, `n_ports`,
   `port_low`/`port_high` — these are not transmitted, only the derived
   ports are.
3. Client computes `HMAC-SHA256(secret, current_30s_time_window)` and turns
   it into an ordered list of ports, then sends one TCP SYN per port, in
   order, with a fixed delay between them.
4. Server watches for exactly that ordered sequence from a source IP. On a
   match (checked against the current window and its two neighbors, to
   tolerate clock skew), it adds the source IP to a timed nftables set,
   which a pre-existing rule matches against to allow the target port —
   the element expires from the set on its own once `open_duration`
   elapses.
5. Replay defense: no nonce in v1. A captured sequence is only valid for
   ~90 seconds (3 time windows), and a `(source_ip, time_window)` tuple can
   only succeed once even within that window. See "Replay defense model"
   in `spec/derivation.md` for the full tradeoff.

## Setup

### Server (needs root or the relevant capabilities)

```
sudo apt install libpcap-dev libssl-dev   # build dependencies
cd server
make
sudo cp knockd.conf.example /etc/knockd/knockd.conf   # edit interface, target_port, etc.
sudo ./knockd --config /etc/knockd/knockd.conf
```

`knockd` calls `ensure_base_ruleset()` on startup, which creates (if
missing) an nftables table/set/chain of its own
(`inet knockd knockd_input`) containing two rules, in order: accept
`target_port` from any IP currently in the timed `knockd_allowed` set,
then drop `target_port` unconditionally. **knockd's chain owns the
complete policy for `target_port` — it does not, and cannot reliably,
depend on a separately-managed deny rule living in another chain.**
nftables evaluates independent base chains hooked at the same point
(e.g. `input`) in priority order, and an `accept` verdict in one chain
does not suppress a `drop`/`reject` decided by a different, later chain —
only a terminal drop/reject anywhere is final. In practice this means: if
`target_port` is also referenced by another firewall chain on this host
(ufw, firewalld, a hand-written iptables/nftables ruleset), that other
rule can still block traffic even after a successful knock, and you need
to remove/reconcile it rather than relying on `base_chain_priority` alone
to "win". Review `nft list ruleset` on your system before relying on this.

### Client

```
cd client
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
sudo .venv/bin/python -m knockc.cli --config knock.conf.example --target <server-ip>
```

Sending raw TCP SYN packets via scapy requires root (or `CAP_NET_RAW`).

## Testing

- **Unit / cross-language parity** (no root, no networking):
  ```
  cd client && .venv/bin/python -m pytest -q
  cd server && make test
  ```
- **End-to-end**: see `spec/derivation.md` for the protocol details and the
  approved plan's verification section for a network-namespace-based local
  test that exercises the real nftables integration without touching the
  host firewall.

## Known limitations (v1)

- TCP SYN only; UDP knocks are reserved as a later addition (the
  derivation core is protocol-agnostic already).
- No nonce-based replay defense, only window-bound + single-use-per-window
  (see `spec/derivation.md`).
- The service port opened on a successful knock is a fixed 1:1 mapping in
  server config, not client-specified.
- No built-in rate limiting of knock attempts per source IP.
