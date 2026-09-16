"""Packet crafting/sending. Only the 'tcp-syn' knock_proto is implemented;
a 'udp' sender can be added here later as a sibling function without
touching derive.py or the derivation logic.
"""
import time

from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send


def send_tcp_syn_knocks(target: str, ports: list[int], interval_ms: int) -> None:
    for i, port in enumerate(ports):
        pkt = IP(dst=target) / TCP(dport=port, flags="S")
        send(pkt, verbose=0)
        if i != len(ports) - 1:
            time.sleep(interval_ms / 1000.0)


def send_knocks(proto: str, target: str, ports: list[int], interval_ms: int) -> None:
    if proto == "tcp-syn":
        send_tcp_syn_knocks(target, ports, interval_ms)
    else:
        raise ValueError(f"unsupported knock_proto {proto!r}")
