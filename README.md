# 🛡️ ShieldFi — Lightweight Wi-Fi Security Auditor

> **Hackathon-ready, defensive-only desktop tool that audits public Wi-Fi before & during connection. No admin needed for MVP, mock mode for reliable demos.**

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Mode](https://img.shields.io/badge/mode-defensive%20only-orange)

### 30-Second Demo
```bash
pip install -r requirements.txt
python main.py --mock --cli --scenario evil_twin
# → RED Threat: Evil Twin 90/100, ARP spoof, DNS hijack

python main.py --mock   # Launch dark dashboard
```

### What It Does (3 Independent Modules)

| Module | What | Needs |
|--------|------|-------|
| **1 — Passive Risk Audit** | Flag Open / WEP / WPA-TKIP + SSID mimicry (OUI vendor check) | No admin, any OS |
| **2 — Evil Twin & Spoof Detector** *(headline)* | Fingerprint BSSID per SSID, NetworkX graph, suspicion score 0-100 with reasons | No admin, same scan |
| **3 — Active Fingerprinting** | 5-sec post-connect: Gateway MAC (ARP spoof) + Canary DNS vs 1.1.1.1/8.8.8.8 | Connected to Wi-Fi |

### Dashboard (Dark Mode, CustomTkinter)
1. **Threat Level Shield** — Green Safe / Yellow Caution / Red Attack (animated)
2. **Nearby AP List** — SSID, BSSID, signal, channel, encryption icons
3. **Why am I unsafe?** — Plain-English explanations

---

## Quick Start

### Which OS are you on? (tell me once)
- **Windows**: `netsh` is built-in — just run, no admin.
- **Linux**: Install NetworkManager: `sudo apt install network-manager` (for `nmcli`). Fallback `iwlist` works too.
- **macOS**: `airport -s` is built-in — just run.
- **Headless / No Wi-Fi**: Use `--mock` — full demo without hardware.

### Install
```bash
git clone https://github.com/manas-3321/shieldFi.git
cd shieldFi
python3 -m venv .venv && source .venv/bin/activate  # optional but recommended
pip install -r requirements.txt
```

### Run — GUI (recommended)
```bash
python main.py                  # Auto-detect OS, fallback to mock if no adapter
python main.py --mock           # Force mock/demo mode
python main.py --mock --scenario all_risky   # Max drama demo
```

### Run — Headless CLI (servers, no GUI)
```bash
python main.py --cli --mock --scenario evil_twin
python main.py --cli            # Try live scan in terminal
```

### Mock Scenarios
- `normal` — 6 clean APs, no threats (Green)
- `evil_twin` — Duplicate CoffeeShop_Free with wrong vendor/channel/encryption (Red)
- `open_risk` — Extra open networks (Yellow)
- `arp_spoof` — Evil twin + gateway with 2 MACs (Red)
- `all_risky` — Everything combined
- `hijacked` — DNS returns private IPs (Red)

---

## Architecture & Folder Structure
See `docs/ARCHITECTURE.md` and `docs/DATA_FLOW.md` (with Mermaid diagram).

```
main.py
config/trusted_networks.json
config/settings.yaml
shieldfi/
  scanner/      # windows.py, linux.py, macos.py, mock.py, monitor.py (optional scapy)
  analysis/     # risk_audit.py, evil_twin.py, networkx_graph.py, oui_lookup.py
  active/       # arp_check.py, dns_check.py, fingerprint.py
  ui/           # app.py, theme.py, components/
  utils/
tests/
docs/
```

## Why CustomTkinter? (not Electron/Flet)
- Pure Python, 1 pip install, looks gorgeous dark by default.
- Beginner friendly — if you know Tkinter, you know CustomTkinter.
- No Node/Flutter, lightweight (<5MB), works on hackathon laptops.

## Troubleshooting

| Error | Fix |
|-------|-----|
| `No module named customtkinter` | `pip install customtkinter` |
| `No OS scanner available` | Enable Mock mode or install `nmcli`/`netsh`/`airport` |
| `Scan returned 0 networks` | Wi-Fi off, or VM without passthrough — use `--mock` |
| GUI doesn't open (headless server) | Use `python main.py --cli --mock` |
| `Scapy not installed` | Optional — only for monitor mode: `pip install scapy` (needs sudo) |

## Testing
```bash
pytest -q
# or without pytest:
python -m pytest tests/ -q
```

## Ethics — Defensive Only
ShieldFi **detects and warns**. No deauth, no spoofing, no interception. See `docs/ETHICS.md`. Only audit networks you own or have permission to test.

## Roadmap (if time)
- [ ] History timeline per location
- [ ] PDF report export
- [ ] Auto-import OS saved networks as trusted
- [ ] Captive portal detection

---

Made for a 3rd-sem CSE Data Science hackathon — modular, commented, type-hinted, beginner-readable.
