# ShieldFi — Architecture

## Why this shape?
Hackathon rule: show a working demo even if time runs out.  
So we build **3 independent modules** that can demo alone:
- Module 1 works with just OS scans (no admin).
- Module 2 adds scoring + graph analysis.
- Module 3 adds post-connect active checks.
- UI wires all three but gracefully degrades if one fails.

## Folder Structure
```
shieldFi/
├── main.py                  # Launcher: GUI or CLI (--cli, --mock)
├── requirements.txt
├── config/
│   ├── trusted_networks.json  # User's known good SSID/BSSID/vendor
│   └── settings.yaml          # Weights, DNS servers, scenarios
├── shieldfi/
│   ├── scanner/
│   │   ├── models.py      # WiFiNetwork dataclass
│   │   ├── base.py        # Abstract BaseScanner
│   │   ├── windows.py     # netsh parser (no admin)
│   │   ├── linux.py       # nmcli + iwlist (no admin)
│   │   ├── macos.py       # airport (no admin)
│   │   ├── mock.py        # Deterministic fake data + evil twin scenario
│   │   └── monitor.py     # scapy Beacon sniff (optional, needs root/monitor)
│   ├── analysis/
│   │   ├── oui_lookup.py  # OUI→vendor (40 entries, flag locally-administered)
│   │   ├── risk_audit.py  # Module1: OPEN/WEP/TKIP/MIMICRY
│   │   ├── evil_twin.py   # Module2: suspicion score 0-100
│   │   └── networkx_graph.py # Graph: nodes=BSSID, edges=same SSID mismatch
│   ├── active/
│   │   ├── arp_check.py   # Gateway MAC validation
│   │   ├── dns_check.py   # Canary DNS vs 1.1.1.1/8.8.8.8
│   │   └── fingerprint.py # Orchestrator ~5s
│   ├── ui/
│   │   ├── app.py         # CustomTkinter dark dashboard
│   │   ├── theme.py       # Colors, fonts, icons
│   │   └── components/    # shield, ap_list, explain_panel
│   └── utils/
│       ├── helpers.py     # BSSID normalize, signal helpers
│       └── logger.py
├── tests/
└── docs/
```

## Tech Stack Choice — Why CustomTkinter?
| Option | Verdict |
|--------|---------|
| **CustomTkinter** (chosen) | Pure Python, 1-file install, dark mode built-in, beginner's existing Tkinter knowledge transfers. No Node, no Flutter, lightweight (<5MB). |
| Flet | Nice, but pulls Flutter binary (~100MB), harder for freshmen, needs browser. |
| Tkinter plain | Dated look — hard to sell to judges. |
| Electron | JS stack, overkill, not Pythonic for Data Science student. |

> Beginners can run `pip install customtkinter` and see a polished dark UI in 2 lines.

## Data Flow
```
[OS Scan OR Mock] --WiFiNetwork[]--> [Module1 RiskAudit] --findings--> [Threat Level]
                                \\--> [Module2 EvilTwin] --score/reasons/graph--> [Threat Level]
                                \\--> [Module3 Active] --ARP+DNS--> [Threat Level]
                                                               |
                                                          [UI Dashboard]
                                                        (Shield + AP List + Explain)
```

## Ethics / Defensive Only
- **No deauth, no spoofing, no sniffing of user traffic.**
- Only reads OS scan results and ARP table + does harmless DNS queries.
- Monitor mode is read-only beacon sniff, clearly separated (`scanner/monitor.py`) and off by default.
- README must tell users to only scan networks they have permission to audit.

## OS Notes
- **Windows**: `netsh wlan show networks mode=bssid` — no admin, English output assumed.
- **Linux**: `nmcli device wifi list` or `iwlist <iface> scanning` — no admin if NetworkManager allows.
- **macOS**: `/System/Library/PrivateFrameworks/.../airport -s` — no admin.
- **Monitor**: `scapy` + `airmon-ng` — needs `sudo` + monitor-capable adapter. Optional bonus.

## How Modules Stay Independent
- Each has its own `tests/test_module*.py` that uses MockScanner — no hardware needed.
- `main.py --cli --mock --scenario evil_twin` demos all 3 in terminal without UI.
- UI can run with just Module1 (comment out others) and still show a shield.
