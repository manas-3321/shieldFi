"""Module 2 — Evil Twin & Spoof Detector (Headline feature).

Logs BSSID/MAC fingerprints per SSID, detects:
- Vendor changes (Cisco -> Unknown)
- Duplicate SSIDs with different BSSID/encryption
- Channel anomalies (identical SSID on conflicting channel, one high-power)

Outputs suspicion score 0-100 with reasons.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple
from collections import defaultdict
from ..scanner.models import WiFiNetwork
from ..analysis.oui_lookup import is_suspicious_vendor
from ..analysis.networkx_graph import build_ap_graph, graph_insights

@dataclass
class SuspicionReason:
    code: str               # e.g. "duplicate_ssid"
    message: str            # plain English
    weight: int             # contribution to score
    evidence: str = ""      # e.g. "CoffeeShop_Free seen on BSSID X (Cisco) and Y (Unknown)"

@dataclass
class SuspicionResult:
    ssid: str
    score: int              # 0-100
    level: str              # "safe" | "suspicious" | "evil_twin_likely"
    reasons: List[SuspicionReason] = field(default_factory=list)
    related_bssids: List[str] = field(default_factory=list)
    graph_insights: Dict = field(default_factory=dict)

class EvilTwinDetector:
    """Stateful-ish detector: keeps history fingerprint per SSID.

    In MVP, history is passed in-memory. Optionally persist to JSON file.
    """

    # Weights sum to 100 — easy to explain to judges
    WEIGHTS = {
        "duplicate_ssid": 30,
        "encryption_mismatch": 25,
        "vendor_change": 20,
        "channel_anomaly": 15,
        "signal_anomaly": 10,
    }

    def __init__(self, history: Dict[str, Dict] = None):
        # history[ssid] = {"vendors": set, "bssids": set, "encryptions": set}
        self.history: Dict[str, Dict] = history or {}

    def update_history(self, networks: List[WiFiNetwork]):
        for n in networks:
            h = self.history.setdefault(n.ssid, {"vendors": set(), "bssids": set(), "encryptions": set(), "channels": set()})
            h["vendors"].add(n.vendor)
            h["bssids"].add(n.bssid)
            h["encryptions"].add(n.short_encryption())
            h["channels"].add(n.channel)

    def analyze(self, networks: List[WiFiNetwork]) -> List[SuspicionResult]:
        """Analyze current scan snapshot."""
        # Group by SSID
        by_ssid: Dict[str, List[WiFiNetwork]] = defaultdict(list)
        for n in networks:
            by_ssid[n.ssid].append(n)

        results: List[SuspicionResult] = []
        for ssid, group in by_ssid.items():
            score = 0
            reasons: List[SuspicionReason] = []
            bssids = [g.bssid for g in group]

            # 1) Duplicate SSID with different BSSIDs (classic evil twin)
            if len(group) > 1:
                # Need distinct BSSIDs
                distinct = len(set(bssids))
                if distinct > 1:
                    reasons.append(SuspicionReason(
                        "duplicate_ssid",
                        f"Same name '{ssid}' broadcast by {distinct} different devices. One may be fake.",
                        self.WEIGHTS["duplicate_ssid"],
                        f"BSSIDs: {', '.join(bssids)}"
                    ))
                    score += self.WEIGHTS["duplicate_ssid"]

                    # 2) Encryption mismatch within same SSID
                    encs = set(g.short_encryption() for g in group)
                    if len(encs) > 1:
                        reasons.append(SuspicionReason(
                            "encryption_mismatch",
                            f"'{ssid}' appears with different security: {', '.join(encs)}. Legit APs keep this consistent.",
                            self.WEIGHTS["encryption_mismatch"],
                            f"Encryptions: {encs}"
                        ))
                        score += self.WEIGHTS["encryption_mismatch"]

                    # 3) Vendor change / suspicious vendor within group
                    vendors = set(g.vendor for g in group)
                    suspicious = [g for g in group if is_suspicious_vendor(g.vendor)]
                    # If one vendor is known (Cisco/TP-Link) and another is Unknown/Locally Administered
                    if len(vendors) > 1 or suspicious:
                        msg = f"Hardware vendor changed for '{ssid}': {', '.join(vendors)}."
                        if suspicious:
                            msg += " A new device uses a hidden/locally-administered MAC — common for software APs."
                        reasons.append(SuspicionReason(
                            "vendor_change",
                            msg,
                            self.WEIGHTS["vendor_change"],
                            f"Vendors: {vendors}"
                        ))
                        score += self.WEIGHTS["vendor_change"]

                    # 4) Channel anomaly — same SSID on far apart channels (e.g., 6 vs 11)
                    channels = sorted(set(g.channel for g in group))
                    if len(channels) > 1:
                        spread = max(channels) - min(channels)
                        if spread >= 5:
                            reasons.append(SuspicionReason(
                                "channel_anomaly",
                                f"'{ssid}' seen on far apart channels {channels}. Legit multi-AP setups usually cluster or split 2.4/5 GHz cleanly.",
                                self.WEIGHTS["channel_anomaly"],
                                f"Channels: {channels}"
                            ))
                            score += self.WEIGHTS["channel_anomaly"]

                    # 5) Signal anomaly — one AP much stronger (attacker close by)
                    signals = sorted([g.signal_dbm for g in group], reverse=True)  # -28 > -70
                    if len(signals) >= 2 and (signals[0] - signals[1] >= 20):
                        reasons.append(SuspicionReason(
                            "signal_anomaly",
                            f"One '{ssid}' signal is unusually strong ({signals[0]} dBm vs {signals[1]} dBm). Attacker's device may be nearby.",
                            self.WEIGHTS["signal_anomaly"],
                            f"Signals: {signals}"
                        ))
                        score += self.WEIGHTS["signal_anomaly"]

            # Also check history-based vendor change (even if only 1 AP now but history had different vendor)
            hist = self.history.get(ssid)
            if hist and len(group) == 1:
                cur_vendor = group[0].vendor
                if cur_vendor not in hist["vendors"] and hist["vendors"]:
                    if is_suspicious_vendor(cur_vendor) or len(hist["vendors"]) > 1:
                        reasons.append(SuspicionReason(
                            "vendor_change",
                            f"'{ssid}' previously seen as {', '.join(hist['vendors'])}, now as {cur_vendor}. Vendor changed — possible spoof.",
                            self.WEIGHTS["vendor_change"],
                            f"History vendors: {hist['vendors']} -> {cur_vendor}"
                        ))
                        score += self.WEIGHTS["vendor_change"]

            if score > 0:
                score = min(score, 100)
                level = "evil_twin_likely" if score >= 60 else "suspicious" if score >= 30 else "safe"
                results.append(SuspicionResult(
                    ssid=ssid, score=score, level=level,
                    reasons=reasons, related_bssids=bssids
                ))

        # Attach graph insights (once for whole scan)
        G = build_ap_graph(networks)
        insights = graph_insights(G)
        for r in results:
            r.graph_insights = insights

        return sorted(results, key=lambda x: x.score, reverse=True)

    def global_suspicion_score(self, results: List[SuspicionResult]) -> int:
        """Max score across SSIDs — for Threat Shield."""
        if not results:
            return 0
        return max(r.score for r in results)

    def plain_explanations(self, results: List[SuspicionResult]) -> List[str]:
        """Return plain English bullet points for UI 'Why am I unsafe?'"""
        lines = []
        for r in results:
            for reason in r.reasons:
                lines.append(f"• [{r.ssid}] {reason.message} (evidence: {reason.evidence})")
        if not lines:
            lines.append("No Evil Twin signs in this scan. Vendors, encryption, and channels look consistent.")
        return lines
