from __future__ import annotations

import threading
from typing import Callable, Optional

try:
    from scapy.all import sniff
except ImportError:  # pragma: no cover
    sniff = None


class PacketSniffer:
    """ lightweight wrapper around scapy sniffing."""

    def __init__(self, iface: str = "eth0", detector=None, packet_handler: Optional[Callable] = None, filter_expr: Optional[str] = None):
        self.iface = iface
        self.detector = detector
        self.packet_handler = packet_handler
        self.filter_expr = filter_expr
        self._stop_event = threading.Event()
        self._thread = None

    def _dispatch_packet(self, packet):
        if self.detector is not None:
            alerts = self.detector.inspect(packet)
            if alerts and self.packet_handler is not None:
                self.packet_handler(packet, alerts)
            elif alerts:
                for alert in alerts:
                    print(alert)
        elif self.packet_handler is not None:
            self.packet_handler(packet, [])

    def start(self, timeout: Optional[float] = None) -> None:
        if sniff is None:
            raise RuntimeError("scapy is required to capture network packets")

        self._stop_event.clear()

        def _capture():
            sniff(
                iface=self.iface,
                prn=self._dispatch_packet,
                store=False,
                timeout=timeout,
                filter=self.filter_expr,
            )

        self._thread = threading.Thread(target=_capture, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)


__all__ = ["PacketSniffer"]
