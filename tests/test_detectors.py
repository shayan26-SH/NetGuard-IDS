from scapy.all import ARP, IP, TCP, Ether

from netguard_ids.detectors import ThreatDetector
from netguard_ids.mitigation import build_arp_reply


def test_arp_spoof_detector_detects_mac_change():
    detector = ThreatDetector()

    first_packet = Ether()/ARP(hwsrc="aa:bb:cc:dd:ee:01", psrc="10.0.0.10", pdst="10.0.0.1")
    second_packet = Ether()/ARP(hwsrc="aa:bb:cc:dd:ee:02", psrc="10.0.0.10", pdst="10.0.0.1")

    assert detector.arp.inspect(first_packet) == []
    alerts = detector.arp.inspect(second_packet)
    assert len(alerts) == 1
    assert alerts[0].category == "arp_spoofing"
    assert alerts[0].severity == "high"


def test_port_scan_detector_detects_threshold():
    detector = ThreatDetector(port_scan_window_seconds=1.0, port_scan_threshold=3)

    for index in range(3):
        packet = IP(src="10.0.0.20", dst="10.0.0.1") / TCP(sport=12345 + index, dport=80, flags="S")
        alerts = detector.port_scan.inspect(packet)

        if index == 2:
            assert len(alerts) == 1
            assert alerts[0].category == "port_scan"


def test_malformed_packet_detector_flags():
    detector = ThreatDetector()
    packet = IP(src="10.0.0.50", dst="10.0.0.1") / TCP(sport=49000, dport=80, flags="")
    alerts = detector.malformed.inspect(packet)
    assert len(alerts) == 1
    assert alerts[0].category == "malformed_tcp"


def test_build_arp_reply_returns_valid_arp_packet():
    packet = build_arp_reply("10.0.0.1", "aa:bb:cc:dd:ee:01", "10.0.0.10", "aa:bb:cc:dd:ee:02")
    assert packet[ARP].op == 2
    assert packet[ARP].psrc == "10.0.0.10"
    assert packet[ARP].pdst == "10.0.0.1"
