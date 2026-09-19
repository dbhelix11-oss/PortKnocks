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
