#!/usr/bin/env python3
"""Generates spec/testvectors.json — the cross-language ground truth for
the knock sequence derivation function described in derivation.md.

Uses only hashlib/hmac (stdlib) so this reference implementation has no
dependency overlap with client/knockc/derive.py, which uses the
`cryptography` package. Run manually when constants change; the output
is checked in, not regenerated at build time.

Protocol v2: the HMAC message is time_counter (8 bytes, big-endian)
concatenated with channel_id (1 byte) -- see derivation.md.
"""
import hashlib
import hmac
import json
from pathlib import Path


def derive_ports(secret: bytes, time_counter: int, channel_id: int, n: int,
                  port_low: int, port_high: int) -> list[int]:
    msg = time_counter.to_bytes(8, "big") + bytes([channel_id])
    digest = hmac.new(secret, msg, hashlib.sha256).digest()
    span = port_high - port_low + 1
    ports = []
    for i in range(n):
        raw16 = int.from_bytes(digest[2 * i:2 * i + 2], "big")
        ports.append(port_low + (raw16 % span))
    return ports


def vector(secret_hex: str, time_counter: int, channel_id: int, n: int,
           port_low: int, port_high: int) -> dict:
    secret = bytes.fromhex(secret_hex)
    return {
        "secret_hex": secret_hex,
        "time_counter": time_counter,
        "channel_id": channel_id,
        "N": n,
        "port_low": port_low,
        "port_high": port_high,
        "ports": derive_ports(secret, time_counter, channel_id, n, port_low, port_high),
    }


def main() -> None:
    secret_a = "00" * 32
    secret_b = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    vectors = [
        vector(secret_a, time_counter=0, channel_id=0, n=6, port_low=20000, port_high=60000),
        vector(secret_a, time_counter=56230123, channel_id=0, n=6, port_low=20000, port_high=60000),
        vector(secret_b, time_counter=1, channel_id=0, n=6, port_low=20000, port_high=60000),
        vector(secret_b, time_counter=2**32 - 1, channel_id=0, n=6, port_low=20000, port_high=60000),
        vector(secret_b, time_counter=56230123, channel_id=0, n=16, port_low=1024, port_high=65535),
        # Non-zero channels: same (secret, time_counter) as vectors above but a
        # different channel_id must produce a *different* sequence -- this is
        # the whole point of hashing channel_id in, not offsetting time_counter.
        vector(secret_a, time_counter=56230123, channel_id=1, n=6, port_low=20000, port_high=60000),
        vector(secret_a, time_counter=56230123, channel_id=3, n=6, port_low=20000, port_high=60000),
        vector(secret_b, time_counter=1, channel_id=10, n=6, port_low=20000, port_high=60000),
    ]
    out_path = Path(__file__).parent / "testvectors.json"
    out_path.write_text(json.dumps(vectors, indent=2) + "\n")
    print(f"wrote {len(vectors)} vectors to {out_path}")


if __name__ == "__main__":
    main()
