"""Optional monitor-mode scanner using scapy (bonus, not required for MVP).

⚠️  ADMIN RIGHTS REQUIRED + monitor mode.
- Linux: sudo airmon-ng start wlan0; then set interface to monitor
- macOS/Windows: not supported in MVP.

This file is intentionally isolated so beginners can ignore it.
The MVP works fully with normal OS scan APIs (no monitor mode).
"""
from typing import List
from .base import BaseScanner
from .models import WiFiNetwork
from ..utils.logger import get_logger

log = get_logger()

class MonitorModeScanner(BaseScanner):
    """Scapy 802.11 Beacon sniffer — detects hidden APs & client probes."""
    name = "monitor"

    def __init__(self, iface: str = "wlan0mon", timeout: int = 10):
        self.iface = iface
        self.timeout = timeout

    def is_available(self) -> bool:
        try:
            import scapy.all  # noqa: F401
            return True
        except ImportError:
            log.warning("Scapy not installed — monitor mode unavailable. pip install scapy")
            return False

    def scan(self) -> List[WiFiNetwork]:
        """Sniff Beacon frames for `timeout` seconds. Requires root + monitor mode."""
        try:
            from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt
        except ImportError:
            return []

        networks: dict[str, WiFiNetwork] = {}

        def handler(pkt):
            if not pkt.haslayer(Dot11Beacon):
                return
            try:
                bssid = pkt[Dot11].addr2
                # Extract SSID from Dot11Elt ID 0
                ssid = ""
                cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
                channel = 1
                encryption = "Open"
                elt = pkt[Dot11Elt]
                while isinstance(elt, Dot11Elt):
                    if elt.ID == 0:
                        ssid = elt.info.decode(errors="ignore")
                    elif elt.ID == 3:
                        channel = int(elt.info[0])
                    elif elt.ID == 48:
                        encryption = "WPA2"
                    elt = elt.payload.getlayer(Dot11Elt)
                if "privacy" in cap.lower():
                    if encryption == "Open":
                        encryption = "WEP or WPA"
                signal_dbm = getattr(pkt, "dBm_AntSignal", -70)
                # Use existing models
                from ..analysis.oui_lookup import vendor_from_bssid
                vendor = vendor_from_bssid(bssid)
                if bssid not in networks:
                    networks[bssid] = WiFiNetwork(
                        ssid=ssid or "<Hidden>", bssid=bssid,
                        signal_dbm=int(signal_dbm), channel=channel,
                        frequency=2412, encryption=encryption, vendor=vendor,
                        extra={"source": "monitor", "cap": cap}
                    )
            except Exception:
                pass

        log.info(f"Monitor sniff on {self.iface} for {self.timeout}s (needs sudo)...")
        try:
            from scapy.all import sniff
            sniff(iface=self.iface, prn=handler, timeout=self.timeout, store=False)
        except PermissionError:
            log.warning("Monitor scan needs admin/root + monitor mode. Skipping.")
        except Exception as e:
            log.warning(f"Monitor scan error: {e}")
        return list(networks.values())
