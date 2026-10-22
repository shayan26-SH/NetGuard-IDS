from __future__ import annotations

from typing import Iterable, Mapping

try:
    from scapy.all import ARP, Ether, sendp
except ImportError:  # pragma: no cover
    ARP = Ether = sendp = None


def build_arp_reply(target_ip: str, target_mac: str, spoofed_ip: str, spoofed_mac: str):
    """Build a valid ARP reply packet that reasserts a trusted mapping."""
    if ARP is None or Ether is None or sendp is None:
        raise RuntimeError("scapy is required for active defense operations")

    return (
        Ether(src=spoofed_mac, dst=target_mac)
        / ARP(
            op=2,
            hwsrc=spoofed_mac,
            psrc=spoofed_ip,
            hwdst=target_mac,
            pdst=target_ip,
        )
    )


def defend_arp(target_ip: str, target_mac: str, spoofed_ip: str, spoofed_mac: str, iface: str = "eth0"):
    """Broadcast a clean ARP reply to correct a poisoned ARP entry."""
    packet = build_arp_reply(target_ip, target_mac, spoofed_ip, spoofed_mac)
    sendp(packet, iface=iface, verbose=0)
    return packet


def broadcast_arp_replies(mappings: Mapping[str, str], iface: str = "eth0") -> Iterable[object]:
    """Send an ARP reply for each trusted IP-to-MAC mapping."""
    sent = []
    for ip_address, mac_address in mappings.items():
        packet = build_arp_reply(ip_address, "ff:ff:ff:ff:ff:ff", ip_address, mac_address)
        sendp(packet, iface=iface, verbose=0)
        sent.append(packet)
    return sent


__all__ = ["build_arp_reply", "defend_arp", "broadcast_arp_replies"]
