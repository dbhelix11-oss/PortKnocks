import json
from pathlib import Path

from knockc.cli import main
from knockc.preview import build_preview_data

VECTORS_PATH = Path(__file__).parents[2] / "spec" / "testvectors.json"


def test_digest_chunk_to_port_mapping_matches_vectors():
    vectors = json.loads(VECTORS_PATH.read_text())
    for v in vectors:
        secret = bytes.fromhex(v["secret_hex"])
        # build_preview_data derives its own time_counter from `now`; pin
        # `now` so the counter matches the vector's exact time_counter.
        now = v["time_counter"] * 30
        data = build_preview_data(secret, time_step=30, n_ports=v["N"],
                                   port_low=v["port_low"], port_high=v["port_high"],
                                   channel_id=v["channel_id"], now=now)
        assert data["counter"] == v["time_counter"]
        assert data["ports"] == v["ports"]
        for i, port in enumerate(data["ports"]):
            chunk = data["digest"][2 * i:2 * i + 2]
            raw16 = int.from_bytes(chunk, "big")
            span = v["port_high"] - v["port_low"] + 1
            assert v["port_low"] + (raw16 % span) == port


def test_preview_flag_exits_cleanly_without_sending(tmp_path, monkeypatch, capsys):
    secret_path = tmp_path / "secret.key"
    secret_path.write_bytes(b"\x00" * 32)
    secret_path.chmod(0o600)

    config_path = tmp_path / "knock.conf"
    config_path.write_text(f"""
[knock]
keyfile = {secret_path}
time_step = 30
n_ports = 6
port_low = 20000
port_high = 60000
knock_interval_ms = 100
knock_proto = tcp-syn
""")

    sent = []
    monkeypatch.setattr("knockc.cli.send_knocks", lambda *a, **k: sent.append((a, k)))

    rc = main(["--config", str(config_path), "--target", "203.0.113.5", "--preview"])

    assert rc == 0
    assert sent == []  # --preview must never call send_knocks
