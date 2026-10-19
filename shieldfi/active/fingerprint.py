"""Active Network Fingerprinting — 5-second post-connect check.

Orchestrates:
 a) Gateway MAC validation (ARP spoof)
 b) Canary DNS test (DNS hijack)

Runs both in parallel for speed; returns unified result.
"""
import time
import concurrent.futures
from dataclasses import dataclass, field
from typing import List, Optional
from .arp_check import check_arp_spoof, ARPCheckResult
from .dns_check import check_dns_hijack, CanaryDNSResult
from ..utils.logger import get_logger

log = get_logger()

@dataclass
class ActiveFingerprintResult:
    duration_sec: float = 0.0
    arp: ARPCheckResult = None
    dns: CanaryDNSResult = None
    overall_safe: bool = True
    threat_level: str = "green"  # green | yellow | red
    summary: str = ""
    plain_explanations: List[str] = field(default_factory=list)

class ActiveFingerprint:
    """Runs ~5 sec check after connecting."""

    def __init__(self, expected_gateway_mac: str = None, trusted_dns=None, canary_domains=None):
        self.expected_gateway_mac = expected_gateway_mac
        self.trusted_dns = trusted_dns or ["1.1.1.1", "8.8.8.8"]
        self.canary_domains = canary_domains or ["example.com", "google.com", "cloudflare.com"]

    def run(self, mock: bool = False, mock_scenario: str = "normal", timeout: float = 5.0) -> ActiveFingerprintResult:
        """Run both checks; mock mode simulates attacks for demo."""
        start = time.time()
        arp_result = None
        dns_result = None

        # If mock, we can still run real logic but inject simulated results for deterministic demo
        if mock:
            # Use mock helpers directly
            arp_result = check_arp_spoof(mock=True, mock_scenario="arp_spoof" if mock_scenario in ("arp_spoof", "all_risky") else "normal")
            dns_result = check_dns_hijack(mock=True, mock_scenario="hijacked" if mock_scenario in ("hijacked", "all_risky") else "normal")
        else:
            # Run in parallel with thread pool (IO-bound)
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                fut_arp = pool.submit(check_arp_spoof, expected_mac=self.expected_gateway_mac)
                fut_dns = pool.submit(check_dns_hijack, self.canary_domains, self.trusted_dns)
                try:
                    arp_result = fut_arp.result(timeout=timeout)
                except concurrent.futures.TimeoutError:
                    log.warning("ARP check timed out")
                    from .arp_check import ARPCheckResult
                    arp_result = ARPCheckResult(reasons=["ARP check timed out"])
                try:
                    dns_result = fut_dns.result(timeout=timeout)
                except concurrent.futures.TimeoutError:
                    log.warning("DNS check timed out")
                    from .dns_check import CanaryDNSResult
                    dns_result = CanaryDNSResult(summary="DNS check timed out")

        elapsed = time.time() - start

        # Determine overall threat
        threat_level = "green"
        safe = True
        explanations: List[str] = []

        if arp_result and arp_result.is_spoof_suspected:
            threat_level = "red"
            safe = False
            explanations.extend([f"ARP: {r}" for r in arp_result.reasons])
        elif arp_result and arp_result.reasons:
            # Non-critical ARP notes still worth showing
            explanations.extend([f"ARP: {r}" for r in arp_result.reasons])

        if dns_result and dns_result.is_hijack_suspected:
            threat_level = "red"
            safe = False
            for r in dns_result.results:
                explanations.extend([f"DNS ({r.domain}): {msg}" for msg in r.reasons])
        elif dns_result and dns_result.results:
            for r in dns_result.results:
                if r.reasons:
                    explanations.extend([f"DNS ({r.domain}): {msg}" for msg in r.reasons])

        if not explanations:
            explanations = ["Active checks clean: gateway MAC looks legitimate and DNS answers match trusted servers."]

        summary = []
        if arp_result:
            summary.append(f"Gateway {arp_result.gateway_ip} → {arp_result.gateway_mac or 'unknown'} ({arp_result.gateway_mac_vendor or 'unknown vendor'})")
        if dns_result:
            summary.append(dns_result.summary)
        summary_text = " | ".join(summary) if summary else "No active data"

        return ActiveFingerprintResult(
            duration_sec=round(elapsed, 2),
            arp=arp_result,
            dns=dns_result,
            overall_safe=safe,
            threat_level=threat_level,
            summary=summary_text,
            plain_explanations=explanations
        )
