"""Packet preview console: shows what a knock attempt would actually send,
and the derivation math that produced it, without sending anything.
"""
import hashlib
import time

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from scapy.layers.inet import IP, TCP

from .derive import compute_digest, ports_from_digest


def key_fingerprint(secret: bytes) -> str:
    """A stable identifier for a key, safe to display -- NOT the secret
    itself. One-way (SHA-256), so it can't be reversed back to the key."""
    return hashlib.sha256(secret).hexdigest()[:16]


def build_preview_data(secret: bytes, time_step: int, n_ports: int, port_low: int, port_high: int,
                        channel_id: int = 0, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    counter = int(now // time_step)
    digest = compute_digest(secret, counter, channel_id)
    ports = ports_from_digest(digest, n_ports, port_low, port_high)
    seconds_remaining = time_step - (now % time_step)
    return {
        "now": now,
        "counter": counter,
        "channel_id": channel_id,
        "digest": digest,
        "ports": ports,
        "seconds_remaining": seconds_remaining,
    }


def _hexdump_with_highlight(raw: bytes, highlight_start: int, highlight_len: int, width: int = 16) -> Text:
    text = Text()
    for row_start in range(0, len(raw), width):
        row = raw[row_start:row_start + width]
        text.append(f"{row_start:04x}  ", style="dim")
        for i, b in enumerate(row):
            offset = row_start + i
            style = "bold black on yellow" if highlight_start <= offset < highlight_start + highlight_len else None
            text.append(f"{b:02x} ", style=style)
        text.append(" " * (3 * (width - len(row))))
        text.append(" ")
        for i, b in enumerate(row):
            offset = row_start + i
            ch = chr(b) if 32 <= b < 127 else "."
            style = "bold black on yellow" if highlight_start <= offset < highlight_start + highlight_len else None
            text.append(ch, style=style)
        text.append("\n")
    return text


def render_preview(secret: bytes, config_path: str, target: str, time_step: int, n_ports: int,
                    port_low: int, port_high: int, channel_id: int = 0, reveal_secret: bool = False,
                    console: Console | None = None) -> dict:
    console = console or Console()
    data = build_preview_data(secret, time_step, n_ports, port_low, port_high, channel_id)

    info = Table.grid(padding=(0, 2))
    info.add_column(style="bold")
    info.add_column()
    info.add_row("Config", config_path)
    info.add_row("Target", target)
    if reveal_secret:
        info.add_row("Secret (raw, --reveal-secret)", secret.hex())
    else:
        info.add_row("Key fingerprint", f"{key_fingerprint(secret)}  [dim](sha256, first 16 hex chars -- not the secret)[/dim]")
    info.add_row("Time step", f"{time_step}s")
    info.add_row("Time counter (window)", str(data["counter"]))
    info.add_row("Window rolls over in", f"{data['seconds_remaining']:.1f}s")
    channel_note = "open primary port" if channel_id == 0 else f"run channel {channel_id}'s configured command"
    info.add_row("Channel", f"{channel_id}  [dim]({channel_note})[/dim]")
    info.add_row("n_ports / port range", f"{n_ports} ports, {port_low}-{port_high}")
    console.print(Panel(info, title="Derivation", border_style="cyan"))

    digest = data["digest"]
    ports = data["ports"]

    chunk_table = Table(title="HMAC digest -> ports  (message = time_counter || channel_id)")
    chunk_table.add_column("i")
    chunk_table.add_column("digest[2i:2i+2]")
    chunk_table.add_column("raw uint16")
    chunk_table.add_column("port[i]")
    for i, port in enumerate(ports):
        chunk = digest[2 * i:2 * i + 2]
        raw16 = int.from_bytes(chunk, "big")
        chunk_table.add_row(str(i), chunk.hex(), str(raw16), str(port))
    console.print(chunk_table)
    console.print(f"[dim]full digest: {digest.hex()}[/dim]\n")

    for i, port in enumerate(ports):
        pkt = IP(dst=target) / TCP(dport=port, flags="S")
        raw = bytes(pkt)
        parsed = IP(raw)
        ip_header_len = parsed.ihl * 4
        dport_offset = ip_header_len + 2  # TCP header: sport(2) dport(2) ...

        hexdump = _hexdump_with_highlight(raw, dport_offset, 2)
        panel_body = Text(f"{len(raw)} bytes, IP+TCP only (no Ethernet framing -- the kernel adds\n"
                           f"that when this is handed to a raw socket at send time)\n\n")
        panel_body.append(hexdump)
        console.print(Panel(panel_body, title=f"Packet {i}: -> {target}:{port}  (TCP SYN)", border_style="green"))

    return data
