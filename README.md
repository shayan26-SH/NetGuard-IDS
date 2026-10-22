# NetGuard-IDS

NetGuard-IDS is a lightweight Python-based network monitoring and active defense tool for detecting suspicious network behavior on local interfaces.

## Features

- Passive packet capture using Scapy
- ARP spoofing detection
- TCP SYN and UDP scan detection
- Malformed TCP flag analysis (NULL / Xmas-style stealth scans)
- Active ARP defense replies to restore legitimate mappings
- CLI dashboard for live monitoring

## Project structure

- `netguard_ids/sniffer.py` — packet capture and callback management
- `netguard_ids/detectors.py` — threat detection rules
- `netguard_ids/mitigation.py` — defensive ARP packet generation and response logic
- `netguard_ids/main.py` — CLI entry point and dashboard
- `tests/test_detectors.py` — verification tests for core logic

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m netguard_ids.main --iface eth0
```

## Notes

This project is designed for trusted, local network monitoring. Use it only on networks where you have authorization to inspect traffic.
