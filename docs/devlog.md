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
