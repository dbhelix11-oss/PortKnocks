"""Knock sequence derivation. Mirrors spec/derivation.md and server/src/derive.cpp
byte-for-byte -- see spec/testvectors.json for the cross-language parity tests.

Protocol v2: the HMAC message is time_counter (8 bytes, big-endian)
concatenated with channel_id (1 byte). channel_id 0 opens its configured
target port(s) (the entire v1 behavior, now possibly more than one port);
1-10 each run a server-configured action -- a command, or opening that
channel's own port(s).
"""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC

NUM_CHANNELS = 11  # valid channel_id values: 0..10


def time_counter(unix_time: float, step_seconds: int) -> int:
    return int(unix_time // step_seconds)


def compute_digest(secret: bytes, counter: int, channel_id: int = 0) -> bytes:
    if not (0 <= channel_id < NUM_CHANNELS):
        raise ValueError(f"channel_id must be in 0..{NUM_CHANNELS - 1}")
    msg = counter.to_bytes(8, "big") + bytes([channel_id])
    h = HMAC(secret, hashes.SHA256())
    h.update(msg)
    return h.finalize()


def ports_from_digest(digest: bytes, n: int, port_low: int, port_high: int) -> list[int]:
    if not (1 <= n <= 16):
        raise ValueError("n must be between 1 and 16 (SHA-256 digest is 16 two-byte chunks)")
    if port_high <= port_low:
        raise ValueError("port_high must be greater than port_low")

    span = port_high - port_low + 1
    ports = []
    for i in range(n):
        raw16 = int.from_bytes(digest[2 * i:2 * i + 2], "big")
        ports.append(port_low + (raw16 % span))
    return ports


def derive_ports(secret: bytes, counter: int, n: int, port_low: int, port_high: int,
                  channel_id: int = 0) -> list[int]:
    digest = compute_digest(secret, counter, channel_id)
    return ports_from_digest(digest, n, port_low, port_high)
