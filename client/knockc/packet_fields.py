"""Pure logic for describing which field of a raw IP+TCP SYN packet a given
byte offset belongs to. Kept separate from inspector.py (which drives the
curses loop) so this is testable without a terminal.
"""
from dataclasses import dataclass

# Known categories, used by inspector.py to pick a persistent highlight
# color per byte group. Kept small and coarse on purpose -- the goal is to
# draw the eye to what matters (identity, the knock itself, flags, protocol
# markers), not to give every field its own color.
CATEGORIES = frozenset({"identity", "port_dest", "port_src", "flags", "protocol", "other"})


@dataclass(frozen=True)
class Field:
    start: int
    end: int  # exclusive
    label: str
    category: str = "other"
    detail: str = ""
    extra: str = ""

    def contains(self, offset: int) -> bool:
        return self.start <= offset < self.end


_IP_FIELD_TEMPLATE = [
    (0, 1, "IP: Version + IHL (Internet Header Length)", "protocol",
     "The high 4 bits are the IP version (4 = IPv4). The low 4 bits are the "
     "header length, measured in 4-byte words -- a value of 5 means a "
     "20-byte header with no options, which is what scapy produces here by "
     "default. Routers and the receiving OS use this to know exactly where "
     "the IP header ends and the TCP header begins."),
    (1, 1, "IP: DSCP + ECN (differentiated services / congestion notification)", "other",
     "Originally called 'Type of Service'; now split into DSCP (traffic "
     "prioritization / QoS hints) and ECN (lets routers signal congestion "
     "without dropping packets). Left at zero here -- a knock packet has no "
     "special queuing needs."),
    (2, 2, "IP: Total Length (header + data, bytes)", "other",
     "The size of this entire packet, header and payload combined. For a "
     "bare TCP SYN with no options and no data this is always 40 (20-byte "
     "IP header + 20-byte TCP header). The receiver uses it to know exactly "
     "where the packet ends, since link-layer framing can pad short frames."),
    (4, 2, "IP: Identification (for fragment reassembly)", "other",
     "A per-packet identifier used to reassemble a packet that got split "
     "into multiple fragments in transit. This packet is far too small to "
     "ever need fragmentation -- the field only exists because every IPv4 "
     "header has one, not because it means anything here."),
    (6, 2, "IP: Flags + Fragment Offset", "other",
     "Controls and tracks IP-level fragmentation: whether this packet may "
     "be split up, and if it already is a fragment, which piece of the "
     "original it is. Scapy defaults both to zero: 'don't fragment, and "
     "this isn't a fragment' -- irrelevant for a packet this small."),
    (8, 1, "IP: TTL (Time To Live, hop limit)", "other",
     "A hop counter, decremented by one at every router that forwards this "
     "packet; when it reaches zero the packet is discarded. This exists "
     "purely to stop packets looping forever if routing is ever "
     "misconfigured. Scapy's default of 64 is an ordinary OS default with "
     "no special meaning for the knock."),
    (9, 1, "IP: Protocol (6 = TCP)", "protocol",
     "Identifies which protocol is carried inside this IP packet -- 6 "
     "means TCP. The receiving OS uses this to hand the rest of the packet "
     "to its TCP stack rather than UDP, ICMP, or anything else."),
    (10, 2, "IP: Header Checksum", "other",
     "A checksum over just the IP header, letting routers and the receiver "
     "detect (not correct) header corruption in transit. Every router that "
     "changes the header -- e.g. decrementing TTL -- recalculates this, so "
     "it isn't tied to this packet's content in any special way."),
    (12, 4, "IP: Source address", "identity",
     "The sender's own IP address. This is what makes the knock's "
     "authorization meaningful: the server remembers 'this exact address "
     "successfully knocked window/channel N' and only opens the port for "
     "that address -- anyone else stays blocked even if they somehow saw "
     "the same sequence."),
    (16, 4, "IP: Destination address", "identity",
     "The address of the machine being knocked on -- the server passively "
     "sniffing for this sequence. Nothing about this field is derived from "
     "the secret; it's simply wherever --target pointed the client."),
]

_TCP_FIELD_TEMPLATE = [
    (0, 2, "TCP: Source port (ephemeral, chosen by the OS/scapy, not derived)", "port_src",
     "An ephemeral port chosen by the OS (via scapy) for this outgoing "
     "attempt -- effectively random, and not derived from the shared "
     "secret at all. TCP always needs a source port, but it plays no role "
     "in the knock's authorization logic; the server only pays attention "
     "to the destination port."),
    (2, 2, "TCP: Destination port -- THIS is the knock", "port_dest",
     "The actual knock. Everything else in this packet is ordinary TCP/IP "
     "plumbing; this one 16-bit field is the only part carrying "
     "information derived from your secret key and the current time "
     "window. The server passively watching for this exact sequence of "
     "destination ports, in order, from the same source IP, within a "
     "matching time window, is the entire authorization mechanism."),
    (4, 4, "TCP: Sequence number", "other",
     "TCP's byte-ordering counter for this connection direction, normally "
     "used so the receiver can reassemble a byte stream in order and "
     "detect loss. This SYN will never be answered or become a real "
     "connection (nothing listens on the destination port), so this is "
     "just a random starting value with no further significance here."),
    (8, 4, "TCP: Acknowledgment number (0 -- unused on a SYN)", "other",
     "Would acknowledge bytes received from the other side -- meaningless "
     "on the very first packet of a connection, since nothing has been "
     "received yet. Always zero here, matching the unset ACK flag."),
    (12, 1, "TCP: Data Offset (header length, in 4-byte words) + reserved bits", "protocol",
     "The high 4 bits give the TCP header's length in 4-byte words (5 = 20 "
     "bytes, no TCP options) -- the TCP equivalent of the IP header's IHL "
     "field. The low 4 bits are reserved and unused."),
    (13, 1, "TCP: Flags (0x02 = SYN)", "flags",
     "The bits that give a TCP segment its meaning -- SYN (0x02) requests "
     "a new connection, ACK (0x10) acknowledges data, FIN/RST end a "
     "connection, and so on. This packet sets only SYN: it looks exactly "
     "like the first packet of a normal connection attempt, which is the "
     "point -- to anyone not watching for the exact knock sequence, it's "
     "indistinguishable from ordinary background noise."),
    (14, 2, "TCP: Window size", "other",
     "How many bytes of data the sender is willing to receive without an "
     "acknowledgment -- part of TCP's flow control. Meaningless here since "
     "no real connection or data transfer ever happens; scapy fills in a "
     "default."),
    (16, 2, "TCP: Checksum", "other",
     "A checksum covering the TCP header, the payload, and part of the IP "
     "header (via a 'pseudo-header'), letting the receiver detect "
     "corruption. Computed automatically by scapy when the packet is "
     "serialized."),
    (18, 2, "TCP: Urgent pointer", "other",
     "Only meaningful when the URG flag is set (it isn't, here) -- would "
     "point to urgent data within the segment. A legacy TCP feature rarely "
     "used today; always zero on this packet."),
]


def build_fields(raw: bytes, digest: bytes, digest_index: int, channel_id: int = 0) -> list[Field]:
    """Builds the full list of labeled byte ranges for one knock packet.

    `digest` and `digest_index` let the destination-port field explain
    exactly which 2-byte slice of the HMAC digest produced this port --
    the whole point of this tool is connecting the wire bytes back to the
    derivation that produced them, not just labeling a generic TCP packet.
    `channel_id` is included in that explanation too, since it's now part
    of what produced `digest` in the first place (see derive.py).
    """
    ip_header_len = (raw[0] & 0x0F) * 4
    tcp_start = ip_header_len
    tcp_data_offset_byte = raw[tcp_start + 12] if len(raw) > tcp_start + 12 else 0x50
    tcp_header_len = (tcp_data_offset_byte >> 4) * 4

    fields = [Field(s, s + l, label, category, detail)
              for s, l, label, category, detail in _IP_FIELD_TEMPLATE if s + l <= ip_header_len]

    for s, l, label, category, detail in _TCP_FIELD_TEMPLATE:
        start = tcp_start + s
        end = start + l
        extra = ""
        if s == 2:  # destination port
            chunk = digest[2 * digest_index:2 * digest_index + 2]
            raw16 = int.from_bytes(chunk, "big") if len(chunk) == 2 else None
            port = int.from_bytes(raw[start:end], "big")
            extra = (f"= HMAC(secret, time_counter || channel_id={channel_id}) "
                     f"digest[{2*digest_index}:{2*digest_index + 2}] = {chunk.hex()} "
                     f"(uint16 {raw16}) -> port {port} (this packet's knock)")
        fields.append(Field(start, end, label, category, detail, extra))

    if tcp_header_len > 20:
        fields.append(Field(tcp_start + 20, tcp_start + tcp_header_len, "TCP: Options", "other",
                             "Optional TCP header extensions (e.g. MSS, window scaling). None are "
                             "set by this client, so this range shouldn't normally appear."))

    payload_start = tcp_start + tcp_header_len
    if payload_start < len(raw):
        fields.append(Field(payload_start, len(raw), "TCP: Payload (empty on a bare SYN)", "other",
                             "Application data, if any. A bare SYN carries none -- this range "
                             "shouldn't normally appear for a knock packet."))

    return fields


def find_field(fields: list[Field], offset: int) -> Field:
    for f in fields:
        if f.contains(offset):
            return f
    return Field(offset, offset + 1, "Unrecognized byte (outside any known field -- report this)",
                  "other", "This byte didn't match any known IP/TCP field -- that's a bug in "
                  "packet_fields.py, not something expected for a real knock packet.")
