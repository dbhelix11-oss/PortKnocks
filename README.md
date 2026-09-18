# PortKnocks

A custom port-knocking authorization system: the sequence of TCP ports a
client must "knock" on is derived from a shared secret, the current time
window, and a channel number (TOTP-style — the same rolling-code idea as a
30-second one-time password), rather than being a static, easily-replayed
sequence. Design notes and the exact derivation algorithm live in
`spec/derivation.md`; the reasoning behind the channel design (and a
rejected alternative with a real cryptographic flaw) is in
`docs/channel-signaling-design.html`. `docs/devlog.md` is a running,
narrative account of how this project was built — start there for the
full story behind any of the design decisions mentioned here.

- `client/` — Python client that computes the sequence, sends the knocks,
  and includes a packet-preview/byte-inspector console (see below).
- `server/` — C++ daemon (`knockd`) that passively sniffs for the
  sequence (via libpcap — it never opens a listening socket on the knock
  ports) and, on a verified match, either opens the target port for that
  source IP (channel 0) or runs a pre-configured command (channels 1-10),
  via an nftables rule with kernel-enforced expiry.
- `spec/` — the language-agnostic derivation spec and cross-language test
  vectors both implementations are checked against.
- `docs/` — the channel-design writeup and the project devlog.

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
3. Client computes `HMAC-SHA256(secret, time_counter || channel_id)` and
   turns it into an ordered list of ports, then sends one TCP SYN per
   port, in order, with a fixed delay between them. `channel_id` selects
   *what* a successful knock does (see "Channels" below), defaulting to
   0 ("open the primary port").
4. Server watches for exactly that ordered sequence from a source IP. On
   a match (checked against the current window and its two neighbors, to
   tolerate clock skew, across all 11 channels), it dispatches based on
   which channel matched.
5. Replay defense: no nonce in v1. A captured sequence is only valid for
   ~90 seconds (3 time windows), and a `(source_ip, time_window,
   channel_id)` tuple can only succeed once even within that window. See
   "Replay defense model" in `spec/derivation.md` for the full tradeoff.

## Channels

A knock sequence means one of 11 things, selected by `channel_id`
(`--channel N` on the client, default `0`):

- **Channel 0**: open the configured `target_port` for the knocking
  source IP, for `open_duration` seconds (or indefinitely for an
  already-established connection — see "Firewall integration" below).
- **Channels 1-10**: run a pre-configured command on the server, with no
  arguments (`[channel.N]` sections in `knockd.conf`, `command = ...`).
  A channel with no configured command logs a warning and does nothing.

`channel_id` is a permanent, public part of the protocol, not a secret —
it's concatenated onto the HMAC message as an independent input
(`time_counter || channel_id`), not implemented as an offset added to
`time_counter`. That alternative was considered and rejected: it aliases
with channel 0's own past/future sequences (a guaranteed replay collision,
not a tunable risk). Full explanation with diagrams in
`docs/channel-signaling-design.html`.

## Setup

### Server (needs root or the relevant capabilities)

```
sudo apt install libpcap-dev libssl-dev nftables   # build + runtime dependencies
cd server
make
sudo mkdir -p /etc/knockd
sudo cp knockd.conf.example /etc/knockd/knockd.conf   # edit interface, target_port, etc.
```

Run it under systemd rather than in a foreground/backgrounded shell —
a plain `sudo ./knockd &` shares your shell's stdout/stderr (so debug
logs interleave with whatever you type) and dies the moment that shell
session ends. `server/knockd.service` is a ready-to-use unit; edit its
`WorkingDirectory`/`ExecStart` paths if your checkout isn't at
`/home/admin/PortKnocks`, then:
```
sudo cp knockd.service /etc/systemd/system/knockd.service
sudo systemctl daemon-reload
sudo systemctl enable --now knockd
journalctl -u knockd -f
```

#### Firewall integration

`knockd` calls `ensure_base_ruleset()` on startup, which creates (if
missing) an nftables table/chain of its own (`inet knockd knockd_input`).
**knockd's chain owns a complete policy — it does not, and cannot
reliably, depend on rules living in a separately-managed chain.**
nftables evaluates independent base chains hooked at the same point
(e.g. `input`) in priority order, and an `accept` verdict in one chain
does not suppress a `drop`/`reject` decided by a different, later chain —
only a terminal drop/reject anywhere is final. In practice this means: if
`target_port` (or anything you want reachable) is also referenced by
another firewall chain on this host (ufw, firewalld, a hand-written
iptables/nftables ruleset), that other chain can still block or allow
traffic independently of knockd's decision — reconcile that separately,
or use `default_deny` below to let knockd manage the whole policy itself.
Review `nft list ruleset` on your system before relying on this.

The chain always starts with `ct state established,related accept`: an
already-open connection's packets keep flowing regardless of the timed
allow-set's expiry (conntrack tracks state per the full 5-tuple, so this
does not also admit a *new* connection from the same source once its
entry has expired — only already-established traffic is exempt). This is
what stops `open_duration` expiring from severing a connection already in
progress.

Two modes, set via `default_deny` in `knockd.conf`:
- **`default_deny = false` (default)**: knockd only ever touches
  `target_port` — an accept rule for knocked-in source IPs, a fallback
  drop for everyone else on that one port. Every other port on the host
  is untouched by this chain.
- **`default_deny = true`**: knockd's chain becomes the default-deny
  authority for the *entire host* — its own policy is `drop`. Ports
  listed in `always_allow_ports` stay reachable regardless of any knock
  (e.g. a decoy/monitored port you always want open); `target_port`
  remains knock-gated; everything else is dropped by the chain's own
  policy. This only works because it's all one chain — a separate
  "block everything except port 22" chain elsewhere on the host will
  **not** reliably override knockd's own accept decisions, for the exact
  reason described above.

### Client

```
cd client
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
sudo .venv/bin/python -m knockc.cli --config knock.conf.example --target <server-ip>
```

Sending raw TCP SYN packets via scapy requires root (or `CAP_NET_RAW`).
Add `--channel N` (0-10) to knock a specific channel; default is `0`.

**Before sending anything for real**, two debugging modes let you see
exactly what would be sent:
```
.venv/bin/python -m knockc.cli --config knock.conf.example --target <server-ip> --preview
.venv/bin/python -m knockc.cli --config knock.conf.example --target <server-ip> --inspect
```
`--preview` (in `client/knockc/preview.py`) renders a static console
(via the `rich` library): the derivation inputs, a table mapping each
HMAC digest chunk to the port it produced, and a hex dump of each actual
knock packet's bytes — and exits without sending anything. `--inspect`
(in `client/knockc/inspector.py` + `client/knockc/packet_fields.py`) is
an interactive `curses`-based byte cursor over the same packets: arrow
keys move byte-by-byte, with persistent color-coding by field category
and a full paragraph explaining each byte's purpose, not just its name.
Both require no network access and send nothing; `--reveal-secret`
(only meaningful with `--preview`) shows the raw secret instead of a
one-way fingerprint, for when you genuinely need to eyeball it.

## Testing

- **Unit / cross-language parity** (no root, no networking):
  ```
  cd client && .venv/bin/python -m pytest -q
  cd server && make test
  ```
- **End-to-end**: `server/tests/e2e_netns_test.sh` and
  `server/tests/e2e_netns_default_deny_test.sh` (both need root) set up
  two network namespaces connected by a veth pair and exercise the real
  libpcap + nftables integration without touching the host firewall —
  see `docs/devlog.md` for what each covers and how they evolved.

## Known limitations (v1)

- TCP SYN only; UDP knocks are reserved as a later addition (the
  derivation core is protocol-agnostic already).
- No nonce-based replay defense, only window-bound + single-use-per-window
  (see `spec/derivation.md`).
- Channel 0's action (open a port) and channels 1-10's action (run a
  command) are each hardcoded to their channel range — a fully
  configurable action-per-channel (so channel 0 could also be
  reconfigured, or any channel could open a port) is a deliberate future
  generalization, not built yet.
- No built-in rate limiting of knock attempts per source IP.
- No true one-shot/single-connection enforcement — a short `open_duration`
  narrows the window during which more than one knock could succeed, but
  doesn't hard-guarantee only one connection ever gets through.
