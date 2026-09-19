# PortKnocks Devlog

This is the narrative log of this project — why things happened, what
broke, what we learned. If you just want a dated list of *what* changed,
that's what a `CHANGELOG.md` is for; this is the version meant to be read
by a human who wasn't in the room.

---

## 2026-09-14 — Starting from a question, not a spec

The project began as an open question: build a port-knocking tool where
the knock sequence is derived from a key rather than hardcoded, but which
key, and in which language? We talked through the options before writing
any code.

The deciding constraint turned out to be entropy, not preference. A knock
sequence can only carry a few bits per knock (a destination port is 16
bits), so a handful of knocks gives you maybe 64-128 bits total — enough
to carry a keyed HMAC (Hash-based Message Authentication Code) output
truncated into port numbers, but nowhere near enough to embed a real RSA
or GPG signature. So "derive knocks from an SSH/GPG/RSA key" really meant:
use a plain symmetric shared secret, fed into an HMAC, combined with the
current time — the same rolling-code idea as a 30-second TOTP (Time-based
One-Time Password) authenticator app. Asymmetric keys would only earn
their keep if the channel were widened to a single encrypted payload
packet (Single Packet Authorization, the approach the mature tool
`fwknop` takes) — a heavier design we deliberately didn't take on for a
first version, though we borrowed its other ideas (keyed HMAC, replay
windows, passive sniffing, fail-closed behavior) rather than its GPG-based
implementation.

Language split: Python for the client (fast to iterate, good crypto
libraries), C++ for the server daemon (low footprint, fits an always-on
process the way `knockd`/`fwknopd`-style tools traditionally are built).

By the end of the session both sides existed and agreed with each other:
an HMAC-SHA256-derived port sequence, TCP SYN knocks, a passive libpcap
sniffer, and nftables doing the actual firewall work — validated end to
end in two network namespaces connected by a veth pair, so none of the
testing ever touched the real host firewall.

## 2026-09-14 — Getting the end-to-end test to actually pass

Getting the pieces built was the easy part; getting the *proof* working
took three tries.

**Try 1** failed on two dumb bugs in the test script itself: the curl
helper accidentally printed `"000"` twice (a stray `|| echo "000"`
fallback firing even when curl itself had already printed the code), and
the Python client couldn't be found (`ModuleNotFoundError: No module named
'knockc'`) because `python -m knockc.cli` was being invoked from outside
the `client/` directory without `PYTHONPATH` set. Both one-line fixes.

**Try 2** got further — the knock was sent, but the protected port still
didn't open. Worse, the daemon's own log file was completely empty, which
turned out to be its own small lesson: `stdout` is fully buffered (not
line-buffered) when it's not attached to a terminal, so every `printf`
call in `knockd` was sitting in a buffer that never got flushed before we
went looking at the log. The fix was to route the daemon's diagnostic
output to `stderr` instead, which glibc leaves unbuffered — a good
reminder that "the log is empty" doesn't mean "nothing happened," it can
just as easily mean "nothing has been flushed yet."

**Try 3**, with real logging in place, showed something much more
interesting: the knock verified successfully, the daemon printed "opening
port," and the port *still* didn't open. That one was a real design bug,
not a test-harness bug. The test's simulated pre-existing firewall lived
in its own nftables table, hooked into `input` at priority 0 with an
unconditional `reject`; `knockd`'s own table hooked in at priority -10 (to
run first) with an `accept` rule. The assumption was that an early
`accept` would win. It doesn't. In Linux's netfilter, separate base chains
hooked at the same point are evaluated independently in priority order —
an `accept` verdict in one chain just means "this chain doesn't object,"
and processing continues to the *next* chain regardless. Only a terminal
`drop`/`reject` is truly final. So the later chain's `reject` fired
unconditionally, no matter what the earlier chain decided. The fix was
architectural, not cosmetic: `knockd` now owns the *complete* policy for
its target port in one chain — an accept rule for the timed allow-set,
followed by an unconditional drop — rather than assuming it could
"out-prioritize" a decision living somewhere else. That's now called out
explicitly in `server/include/firewall.hpp` and `README.md`, since it's
exactly the kind of thing that looks correct, compiles, runs, and is
wrong.

With that fix, the full cycle worked: blocked before the knock, `200 OK`
immediately after a valid sequence, blocked again once `open_duration`
expired.

## 2026-09-14 — Adding a logging scheme

Once the base system worked, the debug `fprintf` calls added along the
way needed to become an actual logging scheme rather than leftover
scaffolding. We settled on: leveled logging (`DEBUG`/`INFO`/`WARN`/
`ERROR`) written to `stderr`, on the assumption that `knockd` will
typically run under systemd, which already captures `stderr` into
`journald` with its own timestamps and rotation — so there was nothing
else to build (no syslog integration, no hand-rolled log files to
rotate). A small self-timestamp was kept anyway so the same lines stay
readable outside journald too (redirected to a plain file, as the
network-namespace test does). Routine per-packet noise (a candidate
starting, a sequence resetting) went to `DEBUG`; a rejected replay went to
`WARN` since it's a mildly interesting signal; a verified knock and
firewall failures went to `INFO`/`ERROR`.

## 2026-09-15 — Two new directions, and a real crypto bug caught early

Two feature ideas came up in the same conversation.

The first: a **packet preview console** for the client — before trusting
the tool, actually *see* the bytes it's about to send, alongside the math
that produced them (the time counter, the HMAC digest, which digest bytes
became which port). This is being built as its own phase, ahead of
everything else, specifically so there's a concrete, visible mental model
of the current single-channel system before more complexity gets layered
on top of it.

The second, bigger idea: extend the single "open a port" function into
**multiple signaling channels** — the same port-knock mechanism
triggering different pre-configured server-side actions (not just opening
a port, but running arbitrary scripts), selected by which of several
distinct sequences was knocked. The original proposal was to generate
extra channels by shifting the time counter by a fixed offset —
`HMAC(secret, time_counter + offset)`. That idea has a real flaw, caught
before any code was written: shifting the *only* input of a
one-argument keyed function just walks along the same function, so
channel k's sequence at window `W` is mathematically identical to channel
0's sequence at window `W + offset_k`. That's not a risk you can shrink
by picking a bigger offset — every such channel's sequence is, by
construction, *also* a perfectly legitimate "open the port" sequence that
occurs at some other real point in time, meaning a captured channel knock
could later be replayed as a genuine open-port command (or vice versa).
The fix was to give the hash a second, independent input instead of
perturbing the one it already had — `HMAC(secret, time_counter ||
channel_id)` — so each channel is a cryptographically unrelated function
of time rather than a shifted view of the same one. Full reasoning,
diagrams, and a jargon glossary were written up as
`docs/channel-signaling-design.html` (an actual illustrated page, at the
user's request, rather than a plain markdown writeup) the same day, ahead
of writing any of the Phase 1 code itself.

Decided scope for that work: 11 channels total, channel 0 keeps today's
hardcoded "open the port" behavior unchanged, channels 1-10 run
pre-configured commands with no arguments. Generalizing "open a port"
itself into just another configurable action (so *any* channel could be
either) was deliberately deferred rather than built now.

Also started this file, for the same reason as the preview console: a
terse `CHANGELOG.md` loses the *why*, and the interesting parts of this
project so far (the buffering bug, the netfilter chain bug, the aliasing
bug) are exactly the parts a changelog would have compressed into one
line each.

## 2026-09-15 — Phase 0: the packet preview console

Built `client/knockc/preview.py` and a `--preview` flag on the existing
CLI. Running it renders three things without sending a single packet: a
panel of the derivation inputs (key fingerprint — never the raw secret,
unless `--reveal-secret` is passed — current time window, seconds until
it rolls over), a table mapping each 2-byte slice of the HMAC digest to
the port it produced, and one hex-dump panel per knock packet with the
destination-port bytes highlighted.

Getting the hex dump right needed one real check, not just cosmetics:
`sender.py` sends via scapy's L3 `send()` (raw IP sockets), so there's no
Ethernet header in what scapy itself builds — `bytes(IP(...)/TCP(...))`
is genuinely the same bytes handed to the OS, not an approximation. The
destination-port offset was computed from the packet's actual serialized
`ihl` (Internet Header Length) field rather than assumed to always be 20
bytes, then verified by hand for one packet: port 32388 is `0x7E84`, and
that's exactly the byte pair the hex dump highlights. Small thing, but
it's the kind of detail that would have silently drifted if two option
flags on the IP header ever changed its length.

A minor refactor came out of this too: `derive.py`'s single
`derive_ports()` function was split into `compute_digest()` +
`ports_from_digest()`, so the preview could show the digest itself
without re-deriving it or duplicating the HMAC call. No behavior change —
covered by the existing parity tests, which still pass unchanged.

## 2026-09-15 — From static preview to an interactive byte cursor

The user tried `--preview` and immediately asked for the natural next
step: move a cursor across the packet and have each byte explained live,
rather than reading a fixed dump top to bottom. Built as `--inspect`, a
separate flag from `--preview` since it takes over the whole terminal
(curses' alternate screen) rather than printing and exiting.

Chose Python's built-in `curses` over `textual` (the richer TUI framework
from the same project as the `rich` library already in use) — no new
dependency, and the interaction needed (arrow keys move a highlighted
cursor, a panel below updates) doesn't need textual's widget system to do
well.

Split the work in two on purpose: `packet_fields.py` holds pure logic —
given a raw packet and the HMAC digest that produced it, which byte
range is which IP/TCP field, and for the destination-port field
specifically, which 2-byte digest slice produced it — with zero
dependency on curses. `inspector.py` is the thin curses loop on top.
The reason for the split wasn't tidiness for its own sake: curses needs
a real controlling terminal to run at all, which means it can't be
driven or verified from a non-interactive shell. Keeping the actual
"which byte means what" logic curses-free meant it could still be fully
unit tested (every byte in a real packet maps to exactly one labeled
field, the destination-port field's explanation names the correct digest
bytes and port) even though the interactive shell itself could only be
verified by the user, in their own terminal.

## 2026-09-15 — Inspector polish: color and depth

After trying `--inspect`, the ask was for two things: color-coded byte
groups so the eye is drawn to what matters without reading every label,
and a real paragraph explaining each field's purpose, not just a
one-line name.

`Field` in `packet_fields.py` grew two new attributes, `category` and
`detail`, populated for every IP/TCP field template entry. Categories
were kept deliberately coarse -- `identity` (the two IP addresses),
`port_dest` (the byte pair that matters most: the knock itself),
`port_src`, `flags`, and `protocol`, with everything else (checksums,
TTL, sequence numbers, window size) left as an uncolored `other` so the
handful of fields worth noticing actually stand out instead of the whole
dump turning into a rainbow. `port_dest` also gets bold in addition to
its color, since it's the one byte pair the entire tool exists to
explain.

One small design choice worth remembering: the cursor highlight changed
from reverse-video to bold+underline. Reverse video would have inverted
a byte's category color right when you point at it -- exactly the moment
you most want to still see what category it belongs to -- so the cursor
now composes with the color instead of fighting it.

The description panel grew a word-wrapped paragraph (via stdlib
`textwrap`, no new dependency) between the existing one-line label and
the digest cross-reference line, so moving onto e.g. the TTL byte now
explains *why* IP packets have a hop limit at all, not just that this
byte is "TTL."

## 2026-09-15/16 — Phase 1: multi-channel signaling, built and verified

Implemented the `channel_id`-as-second-hash-input design from
`docs/channel-signaling-design.html`: the HMAC message grew from 8 bytes
(`time_counter`) to 9 (`time_counter || channel_id`), a breaking protocol
change (protocol v2) requiring client and server to be rebuilt together.
Channel 0 keeps its exact old behavior (open the primary port); channels
1-10 each run a pre-configured command via `fork`+`execve`, no shell, no
arguments.

On the server side, `SessionTracker`'s single `OpenPortCallback` became a
`MatchCallback(source_ip, channel_id)` -- the tracker itself stays
completely ignorant of what a channel *does*; `main.cpp` owns the
dispatch (channel 0 -> `firewall.open_for`, others -> look up
`channel_commands[channel_id]`). The replay cache key grew from
`(source_ip, window)` to `(source_ip, window, channel_id)`, so spending
one channel's window doesn't block another's. The matching loop now
checks all 11 channels across the existing 3-window clock-skew tolerance
-- 33 HMAC evaluations worst case per completed candidate, negligible.

`firewall.cpp`'s fork/exec/waitpid logic got pulled out into a shared
`proc.cpp::exec_and_wait()`, since the new `commands.cpp` (running
channel scripts) needed the exact same pattern -- reuse instead of a
second copy.

The regression test that actually matters here is in `test_session.cpp`:
a channel-3 sequence must produce a match tagged channel 3, never
channel 0, and channel 1's replay-cache entry must not block channel 2 in
the same window. Those two assertions are the concrete proof that the
aliasing bug from the original time-shift idea is actually closed, not
just argued away in the design doc.

## 2026-09-16 — Phase 2: surviving `open_duration`, and a real "default-deny" mode

A direct sequel to the netfilter chain-priority bug from 2026-09-14 --
same underlying lesson, different symptom. The first real knock against
the deployed Honeypot instance worked, but the SSH session it opened got
cut off once `open_duration` (30s) elapsed. The fallback rule
(`tcp dport target_port drop`) matches on destination port alone; it has
no notion of "this packet belongs to a connection I already allowed," so
it drops packets on an *already-established* session just as readily as
a brand-new connection attempt.

The fix is `ct state established,related accept`, inserted as the first
rule in knockd's chain. Conntrack already classifies every packet by
state per the full 5-tuple; established traffic now always matches this
first rule regardless of the timed allow-set's expiry, while a genuinely
new connection attempt (even from the same source IP) is still `new`
state and still has to pass the allow-set check. No new dependency --
`ct` matching is a standard nftables/kernel feature. Complementary,
non-code takeaway: once persistence no longer depends on the timer,
`open_duration` only needs to cover handshake time (a few seconds), not
the whole session -- shrinks the window during which a second, unrelated
knock could also get in, for free.

The more interesting part came from a direct question: "if nftables
blocked everything except port 22, would the knock still open 1221?"
Answer: no, not if that policy lived in a *separate* chain -- it's the
exact same multi-base-chain pitfall as the very first bug in this
project, just approached from the opposite direction this time (the user
asked before building it, rather than us discovering it after). An early
`accept` in knockd's chain doesn't survive a later, independent chain's
deny policy; "deny everything except my decoy port" has to live in
knockd's *own* chain to actually work. Built as an opt-in
`default_deny` + `always_allow_ports` mode in `FirewallConfig`, keeping
today's narrower "only ever touch target_port" behavior as the default so
no existing deployment's other services silently lose access. In
`default_deny` mode the chain's own policy becomes the fallback `drop`,
which also meant the explicit `tcp dport target_port drop` rule from the
narrower mode is now redundant and skipped -- the policy already covers
it.

Two other ideas came up and were explicitly set aside rather than built:
a per-IP firewall exception (imprecise -- conntrack's 5-tuple approach is
strictly more correct, since it wouldn't accidentally admit a *second*
new connection from the same IP), and sshd enforcing a hard
single-connection limit (OpenSSH has no config option for this; building
it ourselves would mean `knockd` detecting handshake completion and
proactively revoking the allow-set entry -- real complexity, noted as a
future option, not built).

New e2e coverage: `e2e_netns_test.sh` gained a scenario that holds a raw
TCP connection open (via bash's `/dev/tcp`, no extra binary needed)
across the `open_duration` boundary and confirms it's still alive
afterward. A new, separate script, `e2e_netns_default_deny_test.sh`,
exercises `default_deny` mode specifically -- and needed one refinement
to actually prove the point: checking for HTTP "not 200" can't
distinguish a firewall *drop* (connection attempt times out) from a port
that's merely closed because nothing's listening (connection refused
immediately) -- both look like "failure" to a naive check. The test now
inspects curl's actual exit code (28 for timeout, 7 for refused) to
confirm unlisted ports are genuinely *dropped*, not just coincidentally
unoccupied. Both e2e scripts passed cleanly, including the new
held-connection scenario, before any of this touched the real instance.

## 2026-09-17/18 — Deploying the fix exposed a bigger problem than the fix itself

Redeploying Phase 2 to the real Honeypot instance kept failing in a way
that looked like the fix wasn't working -- `nft list table inet knockd`
kept showing the *old* 2-rule chain (no `ct state established` rule at
all) no matter how many times the box was rebuilt. Two false leads
first: a stale, non-idempotently-appended ruleset from before the fix
(real, but not the actual blocker once flushed), and `sshd`'s
`ClientAliveInterval` (120s x 3 retries = 360s -- far too lenient to
explain a ~90s cutoff, ruled out cleanly).

Root cause, once actually checked instead of guessed: the *tarball*
being deployed was stale, or in one case the built binary didn't reflect
a rebuild at all (the same class of "make thinks nothing changed because
of preserved timestamps" bug from the very first deployment, recurring).
This is what finally motivated switching the whole deployment path from
scp/tar to a real git-based one: a private GitHub repo, a **read-only
deploy key** generated *on* the Honeypot box (private half never
transmitted, and read-only specifically because a compromise of a box
literally named "Honeypot" should not be able to push anything) --
`git pull` guarantees byte-for-byte parity with what's committed, which
tar with preserved timestamps never did.

Setting the deploy key up hit its own share of friction, all
self-inflicted and all fixed by going back to basics: `git config
core.sshCommand` only applies to the repo it's set in, so it vanished
when a mid-setup ownership mismatch (mixing `sudo git` and plain `git`,
producing a repo half-owned by `root`) forced a full `.git` wipe and
re-init. The fix for a git ownership dispute is never "add more sudo" --
git operations never need root; only starting `knockd` and touching
`nftables` do.

Then, after all of that finally worked and the deploy key correctly
pulled the "fixed" commit down -- **the fix still wasn't there.** Not on
the server, and not even in the *local* working copy on the dev machine,
nor in what had actually been pushed to GitHub in the very first commit.
`firewall.hpp`, `firewall.cpp`, `config.hpp`, `config.cpp`, `main.cpp`'s
Phase 2 changes, and separately `README.md`'s entire Phase 1/2 rewrite,
had all silently reverted to their pre-Phase-2 (in README's case,
pre-Phase-0) state at some point -- while, oddly, the Phase 1 *code*
(channel_id, multi-channel session matching, proc/commands.cpp) and
this devlog's own Phase 0/0c entries survived intact. The most likely
explanation is a sandbox/session persistence boundary somewhere in this
multi-day conversation (the "date has changed" system reminders spanned
several simulated days) reverting local files to an earlier checkpoint --
not a mistake in the design or a git operation gone wrong. The exact
mechanism was never fully pinned down, and wasn't worth chasing further
once the practical fix was clear.

The response was to stop trusting "it compiled" or "git said done" as
proof of anything, and instead verify content directly at every step:
`grep` the source for the expected string, `strings` the compiled
*binary* for the same string (catching a `make` that silently skipped
rebuilding), and `git diff HEAD origin/main` after every push (catching
whether GitHub actually received what was just committed) -- before
ever telling the server to pull. Re-applied all the missing edits,
verified each of the three ways, and only then pushed and redeployed.

Also added `server/knockd.service`: knockd had been running as a
manually backgrounded shell process (`sudo ./knockd ... &`), which
shares the invoking shell's stdout/stderr (debug logs interleaving with
whatever you type) and dies the moment that shell session ends -- not a
real deployment posture. Running it under systemd was already implied by
config comments referencing `journalctl -u knockd`, just never actually
set up until now.

End state, finally confirmed live on the real instance rather than only
in the isolated e2e tests: knock, SSH connects, and the session survives
well past `open_duration` without being cut off -- the original bug
report from two days earlier, actually closed.

## 2026-09-19 — Generalizing "open a port" (finally picking up the deferred item)

Two related pieces of the deferred "generalize the open-a-port action"
item (see the 2026-09-14 entry and `spec/derivation.md`'s "Which service
port opens" section) got built together, since they touch the same
config-parsing and firewall code:

1. **Channels 1-10 can now open a port instead of running a command.**
   Each `[channel.N]` section takes exactly one of `command = <path>` or
   `open_port = <N[, N...]>` (`config.cpp`'s `parse_channel_actions`
   throws if a section sets both). An `open_port` channel gets its own
   nftables set (`knockd_allowed_ch<N>`) and its own accept/drop rule
   pair per port, independent of channel 0's set and every other
   channel's -- so a channel-3 knock can't be replayed to also open
   whatever channel-5 opens, and vice versa. Channel 0 itself is still
   hardcoded to "open ports," not reconfigurable to run a command --
   kept that asymmetry deliberately (see the updated `spec/
   derivation.md`), so no config edit can turn the default channel into
   "run a command" behavior.
2. **`target_port` (and the new `open_port`) now accept a list**, comma-
   and/or whitespace-separated (`22, 80 443`), not just one port. A
   channel-0 knock opens all of `target_port`'s ports together, via the
   same set -- this was the smaller of the two changes since it reuses
   the exact machinery already built for (1): both are just "a named
   port group, opened together by one timed set," whether it's the
   primary group or a channel's own.

`Firewall::setup_port_group()` is the shared piece: given a set name and
a port list, it creates the set and, per port, the accept-if-in-set rule
plus (unless `default_deny`) the explicit drop -- called once for the
primary `target_port` group and once per configured `open_port` channel.
`ensure_base_ruleset()` no longer hardcodes a single target-port rule
pair at all; it's just two calls into that shared helper now.

New `server/tests/test_config.cpp` covers the parsing side (multi-port
lists via both delimiters, single-key channels, the both-keys-is-an-error
case) since there wasn't previously any direct unit coverage of
`config.cpp` -- the existing `make test` target only covered `derive`
and `session`. Not deployed to the real Honeypot instance as part of
this change; its `knockd.conf` still has a single `target_port` and no
`open_port` channels, so behavior there is unaffected until it's
intentionally reconfigured.
