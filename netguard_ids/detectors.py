from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
import threading
import time
from typing import Deque, Dict, Iterable, List

try:
    from scapy.all import ARP, IP, TCP, UDP
except ImportError:  # pragma: no cover - fallback for static analysis and packaging tools
    ARP = IP = TCP = UDP = None


@dataclass(frozen=True)
class Alert:
    category: str
    severity: str
    message: str
    source_ip: str | None = None
    destination_ip: str | None = None

    def __str__(self) -> str:
        return f"[{self.severity}] {self.category}: {self.message}"


class ArpSpoofDetector:
    """Detect ARP replies that rebind an IP to a new MAC address."""

    def __init__(self) -> None:
        self._cache: Dict[str, str] = {}
        self._lock = threading.Lock()

    def inspect(self, packet) -> List[Alert]:
        if ARP is None or not packet.haslayer(ARP):
            return []

        arp = packet[ARP]
        if arp.op not in (1, 2):
            return []

        sender_ip = arp.psrc
        sender_mac = arp.hwsrc
        if not sender_ip or not sender_mac:
            return []

        with self._lock:
            previous = self._cache.get(sender_ip)
            if previous is not None and previous != sender_mac:
                self._cache[sender_ip] = sender_mac
                return [
                    Alert(
                        category="arp_spoofing",
                        severity="high",
                        message=(
                            f"ARP IP {sender_ip} changed from {previous} to {sender_mac}. "
                            "Potential MITM or ARP poisoning attack."
                        ),
                        source_ip=sender_ip,
                        destination_ip=None,
                    )
                ]
            self._cache[sender_ip] = sender_mac
            return []


class PortScanDetector:
    """Flag rapid connection attempts suggesting SYN floods or port sweeps."""

    def __init__(self, window_seconds: float = 2.0, threshold: int = 8) -> None:
        self.window_seconds = window_seconds
        self.threshold = threshold
        self._requests: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def inspect(self, packet) -> List[Alert]:
        if IP is None or not packet.haslayer(IP):
            return []

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        if not src_ip:
            return []

        tcp_or_udp = packet.haslayer(TCP) or packet.haslayer(UDP)
        if not tcp_or_udp:
            return []

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            if not (tcp_layer.flags & 0x02):
                return []
        elif packet.haslayer(UDP):
            pass

        with self._lock:
            now = time.time()
            times = self._requests[src_ip]
            while times and now - times[0] > self.window_seconds:
                times.popleft()
            times.append(now)

            if len(times) >= self.threshold:
                return [
                    Alert(
                        category="port_scan",
                        severity="medium",
                        message=(
                            f"Host {src_ip} generated {len(times)} connection probes within "
                            f"{self.window_seconds:.1f}s. Possible SYN flood or port sweep."
                        ),
                        source_ip=src_ip,
                        destination_ip=ip_layer.dst,
                    )
                ]
            return []


class MalformedPacketDetector:
    """Detect stealth or malformed TCP flag combinations."""

    def __init__(self) -> None:
        self._null_threshold = 0

    def inspect(self, packet) -> List[Alert]:
        if TCP is None or not packet.haslayer(TCP):
            return []

        flags = int(packet[TCP].flags)
        flag_names = []
        if flags == 0:
            flag_names = ["NULL"]
        else:
            if flags & 0x01:
                flag_names.append("FIN")
            if flags & 0x02:
                flag_names.append("SYN")
            if flags & 0x04:
                flag_names.append("RST")
            if flags & 0x08:
                flag_names.append("PSH")
            if flags & 0x10:
                flag_names.append("ACK")
            if flags & 0x20:
                flag_names.append("URG")

        suspicious = flags == 0 or (flags == 0x29) or (flags == 0x01) or (flags == 0x21)
        if not suspicious:
            return []

        description = "NULL scan" if flags == 0 else f"suspicious TCP flags: {', '.join(flag_names)}"
        return [
            Alert(
                category="malformed_tcp",
                severity="medium",
                message=f"Malformed or stealth TCP packet detected: {description}.",
                source_ip=packet[IP].src if packet.haslayer(IP) else None,
                destination_ip=packet[IP].dst if packet.haslayer(IP) else None,
            )
        ]


class ThreatDetector:
    """Convenience wrapper around all detectors."""

    def __init__(self, port_scan_window_seconds: float = 2.0, port_scan_threshold: int = 8) -> None:
        self.arp = ArpSpoofDetector()
        self.port_scan = PortScanDetector(window_seconds=port_scan_window_seconds, threshold=port_scan_threshold)
        self.malformed = MalformedPacketDetector()

    def inspect(self, packet) -> List[Alert]:
        alerts: List[Alert] = []
        alerts.extend(self.arp.inspect(packet))
        alerts.extend(self.port_scan.inspect(packet))
        alerts.extend(self.malformed.inspect(packet))
        return alerts


__all__ = [
    "Alert",
    "ArpSpoofDetector",
    "PortScanDetector",
    "MalformedPacketDetector",
    "ThreatDetector",
]
