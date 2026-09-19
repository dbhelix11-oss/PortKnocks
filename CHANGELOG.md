# Changelog

## 2026-09-19

- Client: `--target` now accepts an `~/.ssh/config` `Host` alias, not just
  an IP/hostname -- resolved via the same `HostName` an `ssh <alias>`
  invocation would use (`client/knockc/sshconfig.py`).
- Server: channels 1-10 can now be configured with `open_port = <N[,
  N...]>` as an alternative to `command = <path>` -- opens that
  channel's own port(s) for the knocking source IP, via its own nftables
  set, instead of running a command. Setting both keys in one
  `[channel.N]` section is a config error.
- Server: `target_port` (and the new `open_port`) now accept a list of
  ports, comma- and/or whitespace-separated (e.g. `22, 80 443`) -- a
  channel-0 knock opens all of them together for the source IP.
- New `server/tests/test_config.cpp` covers the config-parsing side of
  both changes.
- Server: `Firewall::ensure_base_ruleset()` now adds an unconditional
  `iif "lo" accept` rule ahead of every knock-gated rule. Diagnosed live:
  the operator GUI's SSM+SSH tunnel to a knock-gated port kept failing no
  matter how many times or how correctly the box was knocked, because
  `aws ssm start-session ... AWS-StartPortForwardingSession` terminates
  on the instance as a *local* connection to `127.0.0.1:<port>` -- source
  IP `127.0.0.1`, which no knock ever puts in `knockd_allowed` (knocks
  only ever register the real external IP that sent them). Source-IP
  gating can never admit loopback-originated traffic, so this was a
  structural gap, not a missing-port config issue. Safe in both
  `default_deny` modes: a real loopback-sourced TCP connection can't be
  forged by anything off-box over a genuine handshake. Both
  `e2e_netns_test.sh` and `e2e_netns_default_deny_test.sh` now also
  assert the knock-gated port is reachable over `127.0.0.1` from inside
  the server namespace with no valid knock present.
