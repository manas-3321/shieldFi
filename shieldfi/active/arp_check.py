"""ARP spoof / gateway MAC validation.

Detects if gateway MAC is suspicious or changing — classic ARP spoof sign.
Defensive only: observes ARP table, never sends spoofed packets.
"""
import subprocess
import re
import platform
import shutil
from dataclasses import dataclass
from typing import Optional, List, Tuple
from ..utils.logger import get_logger

log = get_logger()

@dataclass
class ARPCheckResult:
    gateway_ip: str = ""
    gateway_mac: str = ""
    gateway_mac_vendor: str = ""
    all_macs_for_gateway: List[str] = None
    is_spoof_suspected: bool = False
    reasons: List[str] = None
    raw_arp: str = ""

    def __post_init__(self):
        if self.all_macs_for_gateway is None:
            self.all_macs_for_gateway = []
        if self.reasons is None:
            self.reasons = []

def get_gateway_ip() -> str:
    """Try to get default gateway IP cross-platform."""
    system = platform.system().lower()
    try:
        if system == "windows":
            res = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=5)
            m = re.search(r"Default Gateway.*:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", res.stdout)
            return m.group(1) if m else ""
        elif system == "darwin":
            res = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True, timeout=5)
            m = re.search(r"gateway:\s*([0-9.]+)", res.stdout)
            return m.group(1) if m else ""
        else:  # linux
            # Try ip route first
            if shutil.which("ip"):
                res = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=5)
                m = re.search(r"default via\s+([0-9.]+)", res.stdout)
                if m:
                    return m.group(1)
            # Fallback netstat
            if shutil.which("netstat"):
                res = subprocess.run(["netstat", "-rn"], capture_output=True, text=True, timeout=5)
                for line in res.stdout.splitlines():
                    if line.startswith("0.0.0.0"):
                        parts = line.split()
                        if len(parts) >= 2:
                            return parts[1]
    except Exception as e:
        log.warning(f"Gateway lookup error: {e}")
    return ""

def get_arp_table() -> str:
    system = platform.system().lower()
    try:
        if system == "windows":
            res = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5)
            return res.stdout
        else:
            if shutil.which("arp"):
                res = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5)
                return res.stdout
            if shutil.which("ip"):
                res = subprocess.run(["ip", "neigh", "show"], capture_output=True, text=True, timeout=5)
                if res.stdout.strip():
                    return res.stdout
    except Exception as e:
        log.warning(f"ARP table error: {e}")
    return ""

def parse_gateway_mac(arp_output: str, gateway_ip: str) -> Tuple[str, List[str]]:
    """Extract MAC(s) associated with gateway IP from ARP output."""
    if not gateway_ip or not arp_output:
        return "", []
    # Find all MACs near gateway IP
    macs = []
    # Normalize gateway IP for search
    for line in arp_output.splitlines():
        if gateway_ip in line:
            m = re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", line)
            if m:
                macs.append(m.group(0).replace("-", ":").upper())
            # ip neigh format: 192.168.1.1 dev wlan0 lladdr AA:BB:CC:DD:EE:FF
            m2 = re.search(r"lladdr\s+([0-9a-fA-F:]{17})", line)
            if m2 and m2.group(1).upper() not in macs:
                macs.append(m2.group(1).upper())
    # Deduplicate
    macs = list(dict.fromkeys(macs))
    primary = macs[0] if macs else ""
    return primary, macs

def check_arp_spoof(gateway_ip: str = None, arp_output: str = None, expected_mac: str = None, mock: bool = False, mock_scenario: str = "normal") -> ARPCheckResult:
    """Main entry — returns ARPCheckResult.

    If mock=True, simulates scenarios without needing real network.
    """
    if mock:
        return _mock_arp_result(mock_scenario)

    if not gateway_ip:
        gateway_ip = get_gateway_ip()
    if not arp_output:
        arp_output = get_arp_table()

    if not gateway_ip:
        return ARPCheckResult(reasons=["Could not determine gateway IP — not connected?"], raw_arp=arp_output)

    gateway_mac, all_macs = parse_gateway_mac(arp_output, gateway_ip)

    result = ARPCheckResult(
        gateway_ip=gateway_ip,
        gateway_mac=gateway_mac,
        all_macs_for_gateway=all_macs,
        raw_arp=arp_output
    )

    # Vendor lookup
    if gateway_mac:
        from ..analysis.oui_lookup import vendor_from_bssid
        result.gateway_mac_vendor = vendor_from_bssid(gateway_mac)

    # Heuristics for spoof suspicion
    reasons = []

    # 1) No MAC found — incomplete ARP
    if not gateway_mac:
        reasons.append("No MAC found for gateway — ARP table incomplete (network may be isolating clients).")

    # 2) Multiple MACs for same gateway IP (ARP flip)
    if len(all_macs) > 1:
        reasons.append(f"Gateway IP {gateway_ip} seen with multiple MACs {all_macs} — possible ARP spoof (attacker + real router both claiming gateway).")
        result.is_spoof_suspected = True

    # 3) Locally administered MAC (second bit set) — software AP / spoof
    if gateway_mac:
        try:
            first_octet = int(gateway_mac.split(":")[0], 16)
            if first_octet & 0x02:
                reasons.append(f"Gateway MAC {gateway_mac} is locally-administered (software AP / virtual) — unusual for a real router. Possible spoof.")
                result.is_spoof_suspected = True
            if gateway_mac.lower() in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                reasons.append("Gateway MAC is all zeros/broadcast — invalid.")
                result.is_spoof_suspected = True
        except ValueError:
            pass

    # 4) Expected MAC mismatch (if user provided baseline)
    if expected_mac and gateway_mac and expected_mac.upper() != gateway_mac.upper():
        reasons.append(f"Gateway MAC changed! Expected {expected_mac}, now {gateway_mac}. Your router's MAC should not change — possible ARP spoof.")
        result.is_spoof_suspected = True

    # 5) Unknown vendor for gateway
    if result.gateway_mac_vendor and "unknown" in result.gateway_mac_vendor.lower():
        reasons.append(f"Gateway vendor unknown ({gateway_mac} → {result.gateway_mac_vendor}). Real routers usually have known vendors (Cisco, TP-Link, etc.).")

    result.reasons = reasons
    if reasons and not result.is_spoof_suspected:
        # Low suspicion still noted
        pass

    return result

def _mock_arp_result(scenario: str) -> ARPCheckResult:
    """Fake ARP results for demo."""
    if scenario == "arp_spoof":
        return ARPCheckResult(
            gateway_ip="192.168.1.1",
            gateway_mac="DE:AD:BE:EF:00:01",
            gateway_mac_vendor="Unknown / Locally Administered (Suspicious)",
            all_macs_for_gateway=["DE:AD:BE:EF:00:01", "00:1A:2B:AA:BB:01"],
            is_spoof_suspected=True,
            reasons=[
                "Gateway IP 192.168.1.1 seen with multiple MACs ['DE:AD:BE:EF:00:01', '00:1A:2B:AA:BB:01'] — possible ARP spoof.",
                "Gateway MAC DE:AD:BE:EF:00:01 is locally-administered (software AP / virtual) — unusual for a real router.",
                "Gateway vendor unknown — real routers usually have known vendors."
            ],
            raw_arp="(mock) ? (192.168.1.1) at de:ad:be:ef:00:01 [ether] on wlan0\n? (192.168.1.1) at 00:1a:2b:aa:bb:01 [ether] on wlan0"
        )
    # Normal
    return ARPCheckResult(
        gateway_ip="192.168.1.1",
        gateway_mac="00:1A:2B:AA:BB:01",
        gateway_mac_vendor="Cisco",
        all_macs_for_gateway=["00:1A:2B:AA:BB:01"],
        is_spoof_suspected=False,
        reasons=["Gateway MAC looks normal: Cisco hardware, single entry. No ARP spoof signs."],
        raw_arp="(mock) ? (192.168.1.1) at 00:1a:2b:aa:bb:01 [ether] on wlan0"
    )
