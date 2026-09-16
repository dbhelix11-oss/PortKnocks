"""Interactive byte-cursor packet inspector. Thin curses loop around the
pure logic in packet_fields.py -- kept separate because curses needs a
real terminal and can't be meaningfully unit-tested.
"""
import curses
import textwrap

from scapy.layers.inet import IP, TCP

from .packet_fields import build_fields, find_field
from .preview import build_preview_data, key_fingerprint

HEX_WIDTH = 16

# category -> (curses color, label) for the persistent (non-cursor) byte
# highlighting. "other" is deliberately left unmapped -- it stays the
# terminal's default color, so the few categories that matter stand out
# instead of everything being colored.
_CATEGORY_COLORS = {
    "identity": (curses.COLOR_CYAN, "address"),
    "port_dest": (curses.COLOR_YELLOW, "destination port (the knock)"),
    "port_src": (curses.COLOR_BLUE, "source port"),
    "flags": (curses.COLOR_GREEN, "flags"),
    "protocol": (curses.COLOR_MAGENTA, "version/protocol"),
}

# The cursor is drawn as bold+underline layered on top of whatever color
# pair the byte already has, rather than reverse video -- reverse would
# fight with, instead of compose with, a colored background/foreground.
_CURSOR_ATTR = curses.A_BOLD | curses.A_UNDERLINE


def _init_colors() -> dict[str, int]:
    curses.start_color()
    try:
        curses.use_default_colors()
        default_bg = -1
    except curses.error:
        default_bg = curses.COLOR_BLACK
    pair_for_category = {}
    for i, (category, (color, _label)) in enumerate(_CATEGORY_COLORS.items(), start=1):
        curses.init_pair(i, color, default_bg)
        pair_for_category[category] = i
    return pair_for_category


def _attr_for(field, pair_for_category: dict, is_cursor: bool) -> int:
    attr = curses.color_pair(pair_for_category.get(field.category, 0))
    if field.category in ("port_dest",):
        attr |= curses.A_BOLD
    if is_cursor:
        attr |= _CURSOR_ATTR
    return attr


def _draw_legend(stdscr, row: int, col: int, max_x: int, pair_for_category: dict) -> None:
    stdscr.addstr(row, col, "legend: ")
    x = col + 8
    for category, (_, label) in _CATEGORY_COLORS.items():
        text = f"[{label}] "
        if x + len(text) >= max_x:
            break
        stdscr.addstr(row, x, text, curses.color_pair(pair_for_category[category]) | curses.A_BOLD)
        x += len(text)


def _draw(stdscr, target: str, fingerprint: str, data: dict, packets: list[dict],
          pkt_idx: int, byte_idx: int, pair_for_category: dict) -> None:
    stdscr.erase()
    max_y, max_x = stdscr.getmaxyx()

    pkt = packets[pkt_idx]
    raw = pkt["raw"]
    fields = pkt["fields"]

    stdscr.addstr(0, 0, "<-/-> move byte   up/down switch packet   q quit"[:max_x - 1])
    stdscr.addstr(1, 0, (f"window {data['counter']}  channel {data['channel_id']}  key fingerprint {fingerprint}"
                          )[:max_x - 1])
    stdscr.addstr(2, 0, (f"packet {pkt_idx + 1}/{len(packets)}  ->  {target}:{pkt['port']}  (TCP SYN, {len(raw)} bytes)"
                          )[:max_x - 1])
    _draw_legend(stdscr, 3, 0, max_x - 1, pair_for_category)

    row = 5
    for row_start in range(0, len(raw), HEX_WIDTH):
        prefix = f"{row_start:04x}  "
        stdscr.addstr(row, 0, prefix)
        col = len(prefix)
        for i in range(row_start, min(row_start + HEX_WIDTH, len(raw))):
            text = f"{raw[i]:02x} "
            field = find_field(fields, i)
            attr = _attr_for(field, pair_for_category, is_cursor=(i == byte_idx))
            if col + len(text) < max_x:
                stdscr.addstr(row, col, text, attr)
            col += len(text)
        row += 1

    row += 1
    field = find_field(fields, byte_idx)
    if row < max_y:
        stdscr.addstr(row, 0, f"byte {byte_idx} (0x{byte_idx:02x}) = 0x{raw[byte_idx]:02x}"[:max_x - 1])
    row += 1
    if row < max_y:
        stdscr.addstr(row, 2, field.label[:max_x - 3],
                      curses.color_pair(pair_for_category.get(field.category, 0)) | curses.A_BOLD)
    row += 2

    for line in textwrap.wrap(field.detail, width=max(20, max_x - 3)):
        if row >= max_y:
            break
        stdscr.addstr(row, 2, line)
        row += 1

    if field.extra:
        row += 1
        for line in textwrap.wrap(field.extra, width=max(20, max_x - 3)):
            if row >= max_y:
                break
            stdscr.addstr(row, 2, line, curses.A_BOLD)
            row += 1

    stdscr.refresh()


def _loop(stdscr, target: str, fingerprint: str, data: dict, packets: list[dict]) -> None:
    curses.curs_set(0)
    pair_for_category = _init_colors()
    pkt_idx = 0
    byte_idx = 0
    while True:
        _draw(stdscr, target, fingerprint, data, packets, pkt_idx, byte_idx, pair_for_category)
        key = stdscr.getch()
        raw_len = len(packets[pkt_idx]["raw"])
        if key == curses.KEY_LEFT:
            byte_idx = max(0, byte_idx - 1)
        elif key == curses.KEY_RIGHT:
            byte_idx = min(raw_len - 1, byte_idx + 1)
        elif key == curses.KEY_UP:
            pkt_idx = (pkt_idx - 1) % len(packets)
            byte_idx = min(byte_idx, len(packets[pkt_idx]["raw"]) - 1)
        elif key == curses.KEY_DOWN:
            pkt_idx = (pkt_idx + 1) % len(packets)
            byte_idx = min(byte_idx, len(packets[pkt_idx]["raw"]) - 1)
        elif key in (ord("q"), ord("Q"), 27):
            return


def run_inspector(secret: bytes, target: str, time_step: int, n_ports: int,
                   port_low: int, port_high: int, channel_id: int = 0) -> None:
    data = build_preview_data(secret, time_step, n_ports, port_low, port_high, channel_id)
    digest = data["digest"]
    fingerprint = key_fingerprint(secret)

    packets = []
    for i, port in enumerate(data["ports"]):
        pkt = IP(dst=target) / TCP(dport=port, flags="S")
        raw = bytes(pkt)
        fields = build_fields(raw, digest, i, channel_id)
        packets.append({"port": port, "raw": raw, "fields": fields})

    curses.wrapper(_loop, target, fingerprint, data, packets)
