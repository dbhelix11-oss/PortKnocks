from scapy.layers.inet import IP, TCP

from knockc.derive import compute_digest, ports_from_digest
from knockc.packet_fields import CATEGORIES, build_fields, find_field


def _make_packet(secret, counter, n, port_low, port_high, digest_index, target="203.0.113.5"):
    digest = compute_digest(secret, counter)
    ports = ports_from_digest(digest, n, port_low, port_high)
    port = ports[digest_index]
    raw = bytes(IP(dst=target) / TCP(dport=port, flags="S"))
    return raw, digest, port


def test_every_byte_maps_to_exactly_one_field():
    secret = b"\x00" * 32
    raw, digest, _ = _make_packet(secret, 0, 6, 20000, 60000, 0)
    fields = build_fields(raw, digest, 0)
    for offset in range(len(raw)):
        field = find_field(fields, offset)
        assert field.contains(offset)
        assert field.label != "Unrecognized byte (outside any known field -- report this)"


def test_destination_port_field_matches_digest_chunk():
    secret = b"\x00" * 32
    digest_index = 2
    raw, digest, port = _make_packet(secret, 0, 6, 20000, 60000, digest_index)

    fields = build_fields(raw, digest, digest_index)
    ip_header_len = (raw[0] & 0x0F) * 4
    dport_offset = ip_header_len + 2

    field = find_field(fields, dport_offset)
    assert field.label == "TCP: Destination port -- THIS is the knock"
    assert str(port) in field.extra

    chunk = digest[2 * digest_index:2 * digest_index + 2]
    assert chunk.hex() in field.extra

    # both bytes of the 2-byte port field resolve to the same field
    assert find_field(fields, dport_offset + 1) == field


def test_source_port_field_has_no_digest_cross_reference():
    secret = b"\x00" * 32
    raw, digest, _ = _make_packet(secret, 0, 6, 20000, 60000, 0)
    fields = build_fields(raw, digest, 0)
    ip_header_len = (raw[0] & 0x0F) * 4

    field = find_field(fields, ip_header_len)  # first byte of TCP header = source port
    assert field.label.startswith("TCP: Source port")
    assert field.extra == ""


def test_every_field_has_a_known_category_and_nonempty_detail():
    secret = b"\x00" * 32
    raw, digest, _ = _make_packet(secret, 0, 6, 20000, 60000, 0)
    fields = build_fields(raw, digest, 0)
    assert fields, "expected at least one field"
    for f in fields:
        assert f.category in CATEGORIES, f"unknown category {f.category!r} on {f.label!r}"
        assert f.detail.strip(), f"empty detail paragraph on {f.label!r}"


def test_destination_port_is_the_only_port_dest_category():
    secret = b"\x00" * 32
    raw, digest, _ = _make_packet(secret, 0, 6, 20000, 60000, 0)
    fields = build_fields(raw, digest, 0)
    port_dest_fields = [f for f in fields if f.category == "port_dest"]
    assert len(port_dest_fields) == 1
    assert port_dest_fields[0].label == "TCP: Destination port -- THIS is the knock"
