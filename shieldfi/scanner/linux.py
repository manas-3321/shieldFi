"""Linux scanner via nmcli (NetworkManager) + fallback to iwlist.

Works WITHOUT monitor mode. Needs normal user; may need no admin.
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

class LinuxScanner(BaseScanner):
    name = "linux"

    def is_available(self) -> bool:
        return shutil.which("nmcli") is not None or shutil.which("iwlist") is not None

    def scan(self) -> List[WiFiNetwork]:
        # Try nmcli first (modern, structured)
        if shutil.which("nmcli"):
            nets = self._scan_nmcli()
            if nets:
                return nets
        # Fallback iwlist
        if shutil.which("iwlist"):
            return self._scan_iwlist()
        log.warning("No nmcli or iwlist found. Install NetworkManager or wireless-tools.")
        return []

    def _scan_nmcli(self) -> List[WiFiNetwork]:
        try:
            # Trigger rescan
            subprocess.run(["nmcli", "device", "wifi", "rescan"], capture_output=True, timeout=5)
            result = subprocess.run(
                ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,FREQ,CHAN,SECURITY", "device", "wifi", "list", "--rescan", "yes"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                # older nmcli may not support --rescan yes
                result = subprocess.run(
                    ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,FREQ,CHAN,SECURITY", "device", "wifi", "list"],
                    capture_output=True, text=True, timeout=10
                )
            return self._parse_nmcli(result.stdout)
        except Exception as e:
            log.warning(f"nmcli scan error: {e}")
            return []

    def _parse_nmcli(self, output: str) -> List[WiFiNetwork]:
        networks: List[WiFiNetwork] = []
        for line in output.strip().splitlines():
            if not line.strip():
                continue
            # nmcli -t uses ':' but SSID may contain ':'. We use careful split: last 5 fields are known
            # Format: SSID:BSSID:SIGNAL:FREQ:CHAN:SECURITY
            # Safer: split from right
            parts = line.rsplit(":", 5)
            if len(parts) != 6:
                continue
            ssid, bssid, signal, freq, chan, security = parts
            ssid = ssid.strip()
            if not ssid:
                ssid = "<Hidden>"
            bssid = normalize_bssid(bssid)
            try:
                signal_dbm = int(int(signal) / 2 - 100) if signal.isdigit() else -70
                freq_mhz = int(freq.replace(" MHz", "").strip()) if freq else 2412
                channel = int(chan) if chan.isdigit() else 1
            except ValueError:
                signal_dbm, freq_mhz, channel = -70, 2412, 1
            encryption = security.strip() if security.strip() else "Open"
            if encryption == "--" or encryption == "":
                encryption = "Open"
            vendor = vendor_from_bssid(bssid)
            networks.append(WiFiNetwork(
                ssid=ssid, bssid=bssid, signal_dbm=signal_dbm,
                channel=channel, frequency=freq_mhz,
                encryption=encryption, vendor=vendor
            ))
        return networks

    def _scan_iwlist(self) -> List[WiFiNetwork]:
        try:
            iface = self._find_iface()
            result = subprocess.run(["iwlist", iface, "scanning"], capture_output=True, text=True, timeout=10)
            return self._parse_iwlist(result.stdout)
        except Exception as e:
            log.warning(f"iwlist scan error: {e}")
            return []

    def _find_iface(self) -> str:
        try:
            res = subprocess.run(["iwconfig"], capture_output=True, text=True, timeout=5)
            m = re.search(r"^(\w+)\s+.*IEEE 802\.11", res.stdout, re.MULTILINE)
            if m:
                return m.group(1)
        except Exception:
            pass
        return "wlan0"

    def _parse_iwlist(self, output: str) -> List[WiFiNetwork]:
        networks: List[WiFiNetwork] = []
        cells = re.split(r"Cell \d+ -", output)
        for cell in cells[1:]:
            essid_m = re.search(r'ESSID:"([^"]*)"', cell)
            bssid_m = re.search(r"Address:\s*([0-9A-F:]{17})", cell, re.I)
            sig_m = re.search(r"Signal level[=:]?\s*(-?\d+)\s*dBm", cell)
            freq_m = re.search(r"Frequency:(\d+\.\d+)", cell)
            chan_m = re.search(r"Channel:(\d+)", cell)
            enc_m = re.search(r"Encryption key:(on|off)", cell, re.I)
            wpa_m = re.search(r"IE:\s*(WPA|IEEE 802\.11i/WPA2)", cell)

            if not bssid_m:
                continue
            bssid = normalize_bssid(bssid_m.group(1))
            ssid = essid_m.group(1) if essid_m else "<Hidden>"
            signal_dbm = int(sig_m.group(1)) if sig_m else -70
            freq = int(float(freq_m.group(1)) * 1000) if freq_m else 2412
            channel = int(chan_m.group(1)) if chan_m else 1
            if enc_m and enc_m.group(1).lower() == "off":
                encryption = "Open"
            elif wpa_m:
                encryption = wpa_m.group(1)
                if "TKIP" in cell:
                    encryption = "WPA-TKIP"
            else:
                encryption = "WEP" if enc_m and enc_m.group(1).lower() == "on" else "Unknown"
            vendor = vendor_from_bssid(bssid)
            networks.append(WiFiNetwork(
                ssid=ssid, bssid=bssid, signal_dbm=signal_dbm,
                channel=channel, frequency=freq, encryption=encryption, vendor=vendor
            ))
        return networks
