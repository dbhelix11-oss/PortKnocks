# Knock Sequence Derivation Spec

This is the single source of truth for how a knock sequence is derived
from the shared secret. The Python client and the C++ server MUST both
implement exactly this algorithm — `testvectors.json` in this directory
exists to prove they agree.

## Constants (must match on both sides, via config)

| Name              | Default | Meaning                                             |
|-------------------|---------|------------------------------------------------------|
| `T`               | 30      | Time step in seconds                                  |
| `N`               | 6       | Number of ports in a knock sequence                    |
| `PORT_LOW`        | 20000   | Lowest derivable port (inclusive)                      |
| `PORT_HIGH`       | 60000   | Highest derivable port (inclusive)                     |
| `KNOCK_INTERVAL_MS` | 100   | Fixed delay between knocks, sent by the client         |
| `OPEN_DURATION`   | 30      | Seconds the target port stays open after a valid knock |
| `knock_proto`     | `tcp-syn` | Wire protocol for knocks (`tcp-syn` in v1; `udp` reserved for later) |
| `NUM_CHANNELS`    | 11      | Valid `channel_id` values: `0..10` (see "Channels" below) |

`N` must satisfy `N <= 16` (a SHA-256 digest is 32 bytes = 16 two-byte
chunks).

> **Protocol v2**: this spec now includes `channel_id` in the HMAC
> message (previously just `time_counter`). This is a breaking change to
> the wire bytes — client and server must be upgraded together. The
> shared secret keyfile itself does not need to change. See
> `docs/channel-signaling-design.html` for the full reasoning behind why
> `channel_id` is a separate hashed input rather than an offset applied
> to `time_counter`.

## Key material

A 32-byte secret, generated once with a CSPRNG:

```
openssl rand -out secret.key 32
```

Distributed out-of-band to client and server, stored with `0600`
permissions on both ends. Never transmitted over the network.

## Time counter

```
time_counter = floor(unix_time / T)
```

Encoded as an **8-byte big-endian unsigned integer** for hashing.

## Derivation function

```
msg    = (time_counter as 8-byte big-endian unsigned int) || (channel_id as 1 byte)
digest = HMAC-SHA256(key = secret, message = msg)   # 32 bytes, 9-byte message
```

`||` is byte concatenation. `channel_id` is a single byte, `0..10` valid
(see "Channels" below).

For `i` in `0 .. N-1`, take the 2-byte chunk `digest[2*i : 2*i + 2]`,
interpret it as a big-endian uint16 `raw16`, and compute:

```
port[i] = PORT_LOW + (raw16 % (PORT_HIGH - PORT_LOW + 1))
```

The resulting `port[0..N-1]` list, in that order, is the knock sequence
for the given `(time_counter, channel_id)` pair.

## Channels

A knock sequence now means one of 11 things, selected by `channel_id`:

- **Channel 0**: open the configured primary port for the knocking
  source IP (this is the entire v1 behavior, now under an explicit id).
- **Channels 1-10**: run a pre-configured command on the server, with no
  arguments. Each channel's command is set independently in server
  config (`[channel.N]` sections); a channel with no configured command
  logs a warning and does nothing.

Channels are **not** a nonce or a security boundary between each other
beyond what the HMAC already provides — `channel_id` is a permanent,
public part of the protocol (like a fixed dial position), not a secret.
Anyone can know channel numbers exist; they still can't produce a valid
sequence for any channel without the shared secret.

Critically, `channel_id` is concatenated onto the message as a second,
independent hash input — it is **not** implemented as an offset added to
`time_counter` (i.e. NOT `HMAC(secret, time_counter + channel_id)`).
That alternative was considered and rejected: shifting the sole input of
a one-argument keyed function doesn't create an independent channel, it
just samples the *same* function at a different point, so a channel's
sequence at window `W` would be identical to channel 0's sequence at
window `W + offset` — a guaranteed aliasing/replay collision, not a
tunable risk. See `docs/channel-signaling-design.html` for the full
explanation with diagrams.

## Client behavior

1. Compute `time_counter` once, at the start of a knock attempt (do not
   recompute mid-sequence).
2. Compute the `N`-port sequence.
3. Send one TCP SYN packet per port, strictly in order, to the target
   host, waiting `KNOCK_INTERVAL_MS` between packets (a monotonic clock
   is used for the spacing itself; only the initial `time_counter` uses
   wall-clock time).

## Server behavior (verification)

The server passively sniffs traffic to `PORT_LOW..PORT_HIGH` (it never
listens on those ports itself). Per source IP, it tracks an ordered list
of observed destination ports ("candidate sequence"):

- A candidate is reset if no new matching packet arrives within a 5
  second inactivity timeout.
- Ordering is strict: a candidate is invalidated (and reset) the moment
  an unexpected packet interleaves — the server does not attempt to
  fuzzy-match a subsequence.
- Once a candidate reaches length `N`, the server checks it against
  three candidate time windows (`anchor - 1`, `anchor`, `anchor + 1`,
  where `anchor` is the `time_counter` computed from the **timestamp of
  the first packet in the candidate**, not "now" at verification time —
  this tolerates clock skew and sequences that straddle a window
  boundary) **for each of the 11 channels** — up to 33 derivations per
  completed candidate, negligible cost.
- The candidate sequence matches a `(window, channel_id)` pair if it is
  byte-for-byte equal, in order, to that pair's derived `port[0..N-1]`.
- On no match against any of the 33 combinations, the candidate is
  dropped silently (fail closed — no signal is returned to the sender,
  to avoid giving an attacker a probing oracle).
- On a match against `(window w, channel c)`, the server checks a replay
  cache keyed by `(source_ip, w, c)` — note the added `c`: a spent
  channel-1 window does not block channel-2 in that same window, and
  vice versa. If already present, the match is rejected (spent).
  Otherwise, the tuple is recorded (TTL `3*T`) and the server dispatches
  on `c` (see "Channels" above): channel 0 opens the configured target
  port for that source IP for `OPEN_DURATION` seconds; channels 1-10 run
  that channel's configured command.

## Replay defense model (explicit tradeoff)

This design does **not** use a per-attempt nonce. A captured sequence is
only valid for the ~90 second span covered by 3 adjacent `T`-second
windows, and the `(source_ip, time_window)` single-use cache means even a
same-window replay by an eavesdropper is rejected once the legitimate
knock has already been consumed. Residual risk: an eavesdropper who
captures a sequence and races the legitimate client to be first to
present it within the same window could win that race. This is
considered acceptable for v1 (mirrors the accepted risk profile of a
TOTP code being replayable until first consumed) and can be closed
further in a later version with a nonce embedded in the packet stream.

## Which service port opens / which command runs

Fixed mapping in server configuration, not transmitted by the client:
channel 0 always opens one pre-configured target port (e.g. "a valid
channel-0 knock opens port 22"); channels 1-10 each run one
pre-configured command. This avoids adding a second,
unauthenticated-until-verified input (e.g. a client-specified port or
command) that the server would need to allowlist-check regardless of how
it arrived. Generalizing this into a fully configurable action per
channel (so channel 0 could also be reconfigured to run a command, or
any channel could open a port) is deliberately deferred — v1 keeps
channel 0's behavior exactly as it was before channels existed.
