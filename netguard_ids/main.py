from __future__ import annotations

import argparse
import time

try:
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table
except ImportError:  # pragma: no cover
    Console = None
    Live = None
    Table = None

from .detectors import ThreatDetector
from .sniffer import PacketSniffer


def _render_console(alert_history: list[str]) -> str:
    if Console is None:
        return "\n".join(alert_history[-10:]) if alert_history else "No alerts observed."

    table = Table(title="NetGuard-IDS")
    table.add_column("Time", style="cyan")
    table.add_column("Alert", style="magenta")

    for entry in alert_history[-10:]:
        timestamp = time.strftime("%H:%M:%S")
        table.add_row(timestamp, entry)

    return table


def main() -> None:
    parser = argparse.ArgumentParser(description="Passive network monitoring and active defense for local LANs.")
    parser.add_argument("--iface", default="eth0", help="Network interface to sniff on")
    parser.add_argument("--filter", default=None, help="Scapy filter expression (optional)")
    parser.add_argument("--timeout", type=float, default=30.0, help="How long to run the sniffer in seconds")
    args = parser.parse_args()

    detector = ThreatDetector(2.0, 8)
    alert_history: list[str] = []

    def handle_packet(packet, alerts):
        for alert in alerts:
            message = str(alert)
            alert_history.append(message)
            print(message)

    sniffer = PacketSniffer(iface=args.iface, detector=detector, packet_handler=handle_packet, filter_expr=args.filter)
    print(f"Starting NetGuard-IDS on interface {args.iface}...")
    sniffer.start(timeout=args.timeout)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping NetGuard-IDS.")
    finally:
        sniffer.stop()


if __name__ == "__main__":
    main()
