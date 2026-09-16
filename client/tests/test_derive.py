import json
from pathlib import Path

import pytest

from knockc.derive import NUM_CHANNELS, derive_ports

VECTORS_PATH = Path(__file__).parents[2] / "spec" / "testvectors.json"


def load_vectors():
    return json.loads(VECTORS_PATH.read_text())


def test_vectors_match():
    vectors = load_vectors()
    assert vectors, "no test vectors loaded"
    for v in vectors:
        secret = bytes.fromhex(v["secret_hex"])
        got = derive_ports(secret, v["time_counter"], v["N"], v["port_low"], v["port_high"], v["channel_id"])
        assert got == v["ports"], f"mismatch for vector {v}"


def test_different_channels_give_different_sequences():
    # This is the whole point of hashing channel_id in rather than
    # offsetting time_counter: two channels at the same time_counter must
    # not produce the same (or a related) sequence.
    secret = b"\x00" * 32
    counter = 56230123
    seqs = [derive_ports(secret, counter, 6, 20000, 60000, c) for c in range(NUM_CHANNELS)]
    assert len(set(tuple(s) for s in seqs)) == NUM_CHANNELS, "expected all channels to be distinct"


def test_rejects_bad_channel_id():
    with pytest.raises(ValueError):
        derive_ports(b"\x00" * 32, 0, 6, 20000, 60000, -1)
    with pytest.raises(ValueError):
        derive_ports(b"\x00" * 32, 0, 6, 20000, 60000, NUM_CHANNELS)


def test_rejects_bad_n():
    with pytest.raises(ValueError):
        derive_ports(b"\x00" * 32, 0, 0, 20000, 60000)
    with pytest.raises(ValueError):
        derive_ports(b"\x00" * 32, 0, 17, 20000, 60000)
