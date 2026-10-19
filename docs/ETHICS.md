# Ethics & Legal Note — ShieldFi

ShieldFi is **defensive only**. It detects risky configurations and warns the user. It does NOT attack, intercept, or disrupt networks.

## What ShieldFi DOES
- Reads OS Wi-Fi scan lists (netsh / nmcli / airport) — same data any device sees.
- Reads local ARP table (`arp -a` / `ip neigh`) — your own device's cache.
- Sends harmless DNS queries to 1.1.1.1 / 8.8.8.8 for `example.com`, `google.com` — normal internet traffic.
- Optionally sniffs 802.11 Beacon frames with `scapy` (read-only, no deauth, no packet injection).

## What ShieldFi NEVER DOES
- No deauthentication attacks, no fake AP creation, no credential harvesting.
- No packet injection, spoofing, ARP poisoning, or DNS spoofing.
- No decryption or eavesdropping on other users' traffic.

## Responsible Use
- Only audit networks you own or have explicit permission to test.
- In many jurisdictions, active probing of networks you don't own may violate local law or terms of service. Use **Mock Mode** for demos if unsure.
- If you find a vulnerable network (open/WEP), **notify the owner**, don't exploit it.

## For Hackathon Judges
This project is intended to **raise awareness** and educate non-technical users. The simulated evil twin / ARP spoof data is synthetic — no real attack is performed.
