"""Mock scanner — deterministic fake data for reliable demos.

WHY: Real scans need hardware & permissions. Mock mode lets you demo 
evil twin / ARP spoof without an actual attacker.
"""
import random
from typing import List
from .base import BaseScanner
from .models import WiFiNetwork
from ..analysis.oui_lookup import vendor_from_bssid

# --- Curated scenarios ---

def _base_networks() -> List[WiFiNetwork]:
    """A clean baseline: 6 APs you might see in a café."""
    return [
        WiFiNetwork(ssid="CoffeeShop_Free", bssid="00:1A:2B:AA:BB:01", signal_dbm=-42, channel=6, frequency=2437, encryption="WPA2-PSK", cipher="CCMP", auth="PSK"),
        WiFiNetwork(ssid="CoffeeShop_Staff", bssid="00:1A:2B:AA:BB:02", signal_dbm=-55, channel=6, frequency=2437, encryption="WPA2-Enterprise", cipher="CCMP", auth="Enterprise"),
        WiFiNetwork(ssid="HomeFiber_5G", bssid="AA:BB:CC:11:22:33", signal_dbm=-68, channel=36, frequency=5180, encryption="WPA3", cipher="CCMP", auth="SAE"),
        WiFiNetwork(ssid="Library_Open", bssid="10:FE:ED:AA:01:01", signal_dbm=-72, channel=11, frequency=2462, encryption="Open", cipher="", auth="Open"),
        WiFiNetwork(ssid="OldRouter_WEP", bssid="28:80:88:CC:DD:01", signal_dbm=-80, channel=1, frequency=2412, encryption="WEP", cipher="WEP", auth="PSK"),
        WiFiNetwork(ssid="Campus_WiFi", bssid="00:1A:2B:AA:BB:CC", signal_dbm=-60, channel=1, frequency=2412, encryption="WPA2-Enterprise", cipher="CCMP", auth="Enterprise"),
    ]

def _evil_twin_networks() -> List[WiFiNetwork]:
    """Attack scenario: Evil Twin duplicates CoffeeShop_Free with stronger signal, open, different vendor/channel."""
    base = _base_networks()
    evil = WiFiNetwork(
        ssid="CoffeeShop_Free",
        bssid="DE:AD:BE:EF:01:99",  # Unknown / Spoofed OUI, locally administered
        signal_dbm=-28,             # Suspiciously strong (attacker nearby)
        channel=11,                # Channel anomaly vs legitimate on ch 6
        frequency=2462,
        encryption="Open",         # Legit is WPA2 — mismatch!
        cipher="",
        auth="Open",
        extra={"note": "EVIL TWIN - simulated attacker AP"}
    )
    # Second evil on same SSID but TKIP (also weak)
    evil2 = WiFiNetwork(
        ssid="Campus_WiFi",
        bssid="12:34:56:78:90:AB",
        signal_dbm=-38,
        channel=13,
        frequency=2472,
        encryption="WPA-TKIP",
        cipher="TKIP",
        auth="PSK",
        extra={"note": "MIMICRY - trusted SSID with wrong vendor/encryption"}
    )
    return base + [evil, evil2]

def _open_risk_networks() -> List[WiFiNetwork]:
    base = _base_networks()
    risky = [
        WiFiNetwork(ssid="Free_Airport_WiFi", bssid="FC:A6:21:11:22:33", signal_dbm=-45, channel=6, frequency=2437, encryption="Open", cipher="", auth="Open"),
        WiFiNetwork(ssid="Hotel_Guest", bssid="FC:A6:21:11:22:44", signal_dbm=-58, channel=6, frequency=2437, encryption="Open", cipher="", auth="Open"),
    ]
    return base + risky

def _all_risky_networks() -> List[WiFiNetwork]:
    # Combine everything for max drama demo
    nets = _evil_twin_networks() + _open_risk_networks()[6:]
    # Deduplicate by BSSID
    seen = {}
    for n in nets:
        seen[n.bssid] = n
    return list(seen.values())

MOCK_SCENARIOS = {
    "normal": _base_networks,
    "evil_twin": _evil_twin_networks,
    "open_risk": _open_risk_networks,
    "all_risky": _all_risky_networks,
    # "arp_spoof" same networks but active check will simulate ARP spoof
    "arp_spoof": _evil_twin_networks,
}

class MockScanner(BaseScanner):
    name = "mock"

    def __init__(self, scenario: str = "evil_twin", jitter: bool = True):
        if scenario not in MOCK_SCENARIOS:
            scenario = "evil_twin"
        self.scenario = scenario
        self.jitter = jitter

    def scan(self) -> List[WiFiNetwork]:
        nets = MOCK_SCENARIOS[self.scenario]()
        # Enrich vendor field
        for n in nets:
            n.vendor = vendor_from_bssid(n.bssid)
        # Add small random signal jitter to look live (deterministic seed)
        if self.jitter:
            rng = random.Random(42)
            for n in nets:
                n.signal_dbm += rng.randint(-2, 2)
        return nets

    def is_available(self) -> bool:
        return True
