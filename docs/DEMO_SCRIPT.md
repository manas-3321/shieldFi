# Demo Script + 2-Minute Pitch + Judge Q&A

## Pre-Demo Checklist (2 min before)
- `pip install -r requirements.txt` (or `pip install customtkinter networkx dnspython requests scapy`)
- `python main.py --mock --scenario evil_twin --cli` → verify output shows RED threat.
- Open GUI: `python main.py --mock` → click Scan, verify Red shield + flagged APs.
- Have fallback: `python main.py --cli --mock --scenario normal` to show green safe state.
- Close extra windows, set dark mode, projector-friendly font scale.

## 2-Minute Pitch (say this)
> "Public Wi-Fi is a trap: 60% of café/airport hotspots are open or use broken WEP/TKIP, and anyone can clone a name like 'CoffeeShop_Free' to steal logins. ShieldFi is a lightweight desktop guardian that audits Wi-Fi before you connect and during your session.
> 
> In Module 1, we scan nearby networks and flag open, WEP, TKIP, and SSID mimicry by checking the hardware vendor via OUI lookup — so a fake copy of your saved 'HomeFiber' lights up instantly.
> 
> Module 2 is our headline: we fingerprint BSSID per SSID, build a NetworkX graph of relationships, and score evil twins on vendor change, encryption mismatch, channel anomalies, and signal strength. You get a 0-100 suspicion score with plain-English reasons.
> 
> Module 3 runs a 5-second active check after you connect — validating the gateway MAC to catch ARP spoofing and doing canary DNS lookups via 1.1.1.1 to catch DNS hijacking.
> 
> All of this lives in a sleek dark-mode dashboard with a Threat Shield — green safe, yellow caution, red active attack — plus a 'Why am I unsafe?' panel a non-technical user can understand. It works without admin or monitor mode, using normal OS scan APIs, and has a mock mode so we can demo reliably. Defensive only — we never attack. Thank you!"

## 5-Min Live Demo Flow
1. **Hook (20s)**: Show phone Wi-Fi list with 5 'Free Wi-Fi' names — ask audience which is safe. Click Scan on ShieldFi → Red shield appears, flagged APs.
2. **Module 1 (40s)**: Point to AP list: "Library_Open is Open — anyone can sniff you" → Explain panel shows plain English.
3. **Module 2 (60s)**: "Look: CoffeeShop_Free appears twice — real Cisco on channel 6, fake locally-administered MAC on channel 11, Open vs WPA2. Graph shows edge, score 90/100."
4. **Module 3 (30s)**: Click "Active Check (5s)" → ARP shows two MACs for 192.168.1.1, DNS shows 192.168.1.100 for example.com → Red confirmed.
5. **Safe contrast (20s)**: Switch scenario to `normal` → Scan → Green shield, "All secure."
6. **Wrap (10s)**: "Pure Python, modular, no admin needed, ethics-first. Code on GitHub, mock mode runs anywhere."

## Likely Judge Questions & Answers

**Q: How do you know Evil Twin vs legit multi-AP enterprise?**
A: Legit enterprise typically uses same vendor (all Cisco), same encryption, coordinated channels (1/6/11) and similar signal. Evil twin scores low then. Our heuristic weights vendor+encryption highest (55pts) so legit scores <30 (yellow, not red). We also flag only if suspicious vendor (locally-administered) or encryption downgrade. Future: learn baseline per location.

**Q: Why NetworkX? Isn't it overkill?**
A: Graph makes relationships visible for demo + interview story. Nodes=BSSID, edges=same SSID mismatch. Density and most-connected AP reveal hub attacker. For judges, it's a one-liner story: "We use data science to find the attack hub."

**Q: Can you do this without admin/monitor mode?**
A: Yes — MVP uses netsh/nmcli/airport, all user-level. Monitor mode (scapy sniff) is optional bonus for hidden APs, isolated in `scanner/monitor.py`. We clearly separate admin vs non-admin code and demo without it.

**Q: False positives? Open network in library isn't always attack.**
A: We distinguish: Open → Yellow (caution, not red). Red only if Evil Twin score ≥60 or ARP/DNS active attack. UI says "Avoid logging in" for Yellow, "Disconnect now" for Red. User decides, we educate.

**Q: DNS hijack detection fails on captive portals?**
A: Good catch — captive portals intentionally hijack DNS to login page. We note that in UI: if local DNS returns private IP but trusted also fails or same, we mark "inconclusive (captive portal?) — log in via trusted VPN." Future: detect portal by fetching http://captive.apple.com.

**Q: What if attacker clones BSSID/MAC too?**
A: Perfect clone is hard to detect passively — signal/channel anomaly still helps (attacker nearby = stronger). Active ARP check catches even cloned MAC if gateway MAC flips. Ultimate defense: use VPN/WPA3-Enterprise. We state this limitation honestly.

**Q: Performance? 5-second check blocks UI?**
A: No — we run ARP+DNS in thread pool with timeouts, UI stays responsive. Scan caches 5s (settings.yaml).

**Q: Why CustomTkinter not Electron?**
A: Our user is a 3rd-sem Data Science student — Python-only, 1 pip install, no Node/Flutter. Dark mode in 1 line, looks polished for judges, lightweight for laptops.

**Q: Ethics — aren't you building a hacking tool?**
A: Defensive only: we read scan lists and ARP tables, do harmless DNS queries. No deauth, no spoof, no interception. README has ethics note, code refuses to send attack packets.

**Q: How to extend?**
A: Add history timeline (track SSID over days), export PDF report, browser extension to warn before login, integrate OS trusted networks auto-import.
