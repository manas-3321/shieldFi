"""Module 1 — Passive Risk Audit (Easy).

Flags: open, WEP, WPA-TKIP, and SSID mimicry.
WHY: Open/WEP/TKIP are broken or unencrypted → easy to sniff traffic.
Mimicry catches attacker copying a trusted SSID but with different hardware.
"""
from dataclasses import dataclass
from typing import List, Dict
from ..scanner.models import WiFiNetwork

@dataclass
class RiskFinding:
    network: WiFiNetwork
    risk: str               # "OPEN", "WEP", "TKIP", "MIMICRY", "WEAK"
    severity: str           # "low", "medium", "high", "critical"
    message: str            # Plain English for non-technical users
    score: int              # 0-100 contribution

# Risk weights (higher = more dangerous)
RISK_WEIGHTS = {
    "OPEN": 90,
    "WEP": 85,
    "TKIP": 70,
    "MIMICRY": 80,
    "WEAK_WPA": 30,
}

CIPHER_EXPLANATIONS = {
    "OPEN": "This Wi-Fi has no password. Anyone nearby can see your unencrypted traffic (like HTTP sites, DNS queries). Avoid logging into anything sensitive.",
    "WEP": "WEP encryption was broken in 2001. It can be cracked in minutes. Treat it as open.",
    "TKIP": "WPA with TKIP is outdated and vulnerable to packet injection. Prefer WPA2-CCMP or WPA3.",
    "MIMICRY": "This network name matches a trusted network you saved before, but the hardware vendor is different. It could be a copycat (Evil Twin) trying to trick you.",
    "WEAK_WPA": "WPA2 without strong settings — usable but not ideal. WPA3 is better.",
}

class PassiveRiskAuditor:
    """Stateless audit — feed it scan results + trusted networks."""

    def __init__(self, trusted_networks: List[Dict] = None):
        # trusted_networks: [{"ssid": "HomeFiber_5G", "bssid": "AA:BB:CC:...", "vendor": "TP-Link"}]
        self.trusted = trusted_networks or []
        # Index by SSID for quick lookup
        self.trusted_by_ssid: Dict[str, Dict] = {t["ssid"]: t for t in self.trusted}

    def audit(self, networks: List[WiFiNetwork]) -> List[RiskFinding]:
        findings: List[RiskFinding] = []
        for net in networks:
            # 1. Encryption checks
            enc = net.short_encryption()
            if enc == "Open":
                findings.append(RiskFinding(net, "OPEN", "critical", CIPHER_EXPLANATIONS["OPEN"], RISK_WEIGHTS["OPEN"]))
            elif enc == "WEP":
                findings.append(RiskFinding(net, "WEP", "critical", CIPHER_EXPLANATIONS["WEP"], RISK_WEIGHTS["WEP"]))
            elif enc == "WPA-TKIP":
                findings.append(RiskFinding(net, "TKIP", "high", CIPHER_EXPLANATIONS["TKIP"], RISK_WEIGHTS["TKIP"]))

            # 2. SSID Mimicry — same SSID as trusted but different vendor/OUI prefix
            if net.ssid in self.trusted_by_ssid:
                trusted = self.trusted_by_ssid[net.ssid]
                trusted_vendor = trusted.get("vendor", "").lower()
                trusted_bssid = trusted.get("bssid", "").lower()
                # Normalize OUI: first 3 octets
                trusted_oui = ":".join(trusted_bssid.split(":")[:3]) if trusted_bssid else ""
                net_oui = ":".join(net.bssid.split(":")[:3]).lower()
                # Flag if OUI differs AND vendor differs (or unknown)
                if trusted_oui and net_oui != trusted_oui.lower():
                    findings.append(RiskFinding(
                        net, "MIMICRY", "high",
                        f"{CIPHER_EXPLANATIONS['MIMICRY']} (Expected ~{trusted_vendor or trusted_oui}, saw {net.vendor} / {net.bssid})",
                        RISK_WEIGHTS["MIMICRY"]
                    ))
                elif trusted_vendor and trusted_vendor != net.vendor.lower() and "unknown" not in net.vendor.lower():
                    # Vendor mismatch without BSSID — still suspicious
                    findings.append(RiskFinding(
                        net, "MIMICRY", "medium",
                        f"Vendor changed for known network '{net.ssid}': was {trusted_vendor.title()}, now {net.vendor}. Could be new hardware — or a spoof.",
                        50
                    ))
        return findings

    def overall_level(self, findings: List[RiskFinding]) -> str:
        """Return green/yellow/red for Threat Shield."""
        if any(f.severity == "critical" for f in findings):
            # distinguish open vs active attack? For Module1, critical open => Yellow/Weak
            # We'll let Module2 upgrade to Red if evil twin detected
            return "yellow"
        if any(f.severity in ("high", "medium") for f in findings):
            return "yellow"
        return "green"

    def plain_summary(self, findings: List[RiskFinding]) -> str:
        if not findings:
            return "All scanned networks use modern encryption. No mimicry detected."
        # Group by risk
        by_risk: Dict[str, int] = {}
        for f in findings:
            by_risk[f.risk] = by_risk.get(f.risk, 0) + 1
        parts = []
        for k, v in by_risk.items():
            parts.append(f"{v}× {k}")
        return "Found " + ", ".join(parts) + ". Check 'Why am I unsafe?' for details."
