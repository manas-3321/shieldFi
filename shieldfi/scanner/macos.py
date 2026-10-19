"""macOS scanner via airport.

Works WITHOUT admin — uses Apple's airport CLI.
Path: /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport
"""
import subprocess
import re
import shutil
from typing import List
from .base import BaseScanner
from .models import WiFiNetwork
from ..analysis.oui_lookup import vendor_from_bssid
from ..utils.logger import get_logger
from ..utils.helpers import normalize_bssid

log = get_logger()

AIRPORT = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"

class MacOSScanner(BaseScanner):
    name = "macos"

    def is_available(self) -> bool:
        return shutil.which("airport") is not None or __import__("os").path.exists(AIRPORT)

    def scan(self) -> List[WiFiNetwork]:
        cmd = AIRPORT if __import__("os").path.exists(AIRPORT) else "airport"
        try:
            result = subprocess.run([cmd, "-s"], capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                log.warning(f"airport failed: {result.stderr}")
                return []
            return self._parse(result.stdout)
        except Exception as e:
            log.warning(f"macOS scan error: {e}")
            return []

    def _parse(self, output: str) -> List[WiFiNetwork]:
        networks: List[WiFiNetwork] = []
        lines = output.strip().splitlines()
        if not lines:
            return []
        # First line is header: SSID BSSID RSSI CHANNEL HT CC SECURITY
        for line in lines[1:]:
            if not line.strip():
                continue
            # airport columns are fixed-width-ish; BSSID is fixed pattern
            bssid_m = re.search(r"([0-9a-fA-F:]{17})", line)
            if not bssid_m:
                continue
            bssid = normalize_bssid(bssid_m.group(1))
            # SSID is leading text before BSSID
            ssid = line[:bssid_m.start()].strip()
            # RSSI, Channel after BSSID
            after = line[bssid_m.end():].strip().split()
            try:
                rssi = int(after[0]) if after else -70
                channel = int(after[1].split(",")[0]) if len(after) > 1 else 1
            except ValueError:
                rssi, channel = -70, 1
            security = " ".join(after[4:]) if len(after) > 4 else "Open"
            if not security or security == "NONE":
                encryption = "Open"
            elif "WEP" in security:
                encryption = "WEP"
            elif "WPA" in security and "TKIP" in security:
                encryption = "WPA-TKIP"
            else:
                encryption = security
            freq = 2412 if channel <= 14 else 5180
            vendor = vendor_from_bssid(bssid)
            networks.append(WiFiNetwork(
                ssid=ssid or "<Hidden>", bssid=bssid, signal_dbm=rssi,
                channel=channel, frequency=freq, encryption=encryption, vendor=vendor
            ))
        return networks
