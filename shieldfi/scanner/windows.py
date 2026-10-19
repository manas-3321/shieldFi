"""Windows scanner via netsh.

Works WITHOUT admin/monitor mode — uses normal OS scan API.
Requires: Windows, Wi-Fi adapter on, run as normal user.
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

class WindowsScanner(BaseScanner):
    name = "windows"

    def is_available(self) -> bool:
        return shutil.which("netsh") is not None

    def scan(self) -> List[WiFiNetwork]:
        if not self.is_available():
            log.warning("netsh not found — are you on Windows?")
            return []
        try:
            # netsh output is localized; we handle English parsing, fallback gracefully
            result = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                log.warning(f"netsh failed: {result.stderr.strip()}")
                return []
            return self._parse(result.stdout)
        except FileNotFoundError:
            log.warning("netsh not found")
            return []
        except subprocess.TimeoutExpired:
            log.warning("netsh timed out")
            return []
        except Exception as e:
            log.warning(f"Windows scan error: {e}")
            return []

    def _parse(self, output: str) -> List[WiFiNetwork]:
        networks: List[WiFiNetwork] = []
        # netsh blocks separated by SSID lines
        ssid_blocks = re.split(r"SSID \d+ :", output)
        for block in ssid_blocks[1:]:
            lines = block.strip().splitlines()
            if not lines:
                continue
            ssid = lines[0].strip().strip('"')
            if not ssid:
                continue  # hidden network, still record
            # Find fields
            auth = ""
            cipher = ""
            encryption = "Unknown"
            bssids = []
            # Collect BSSID sections inside this SSID block
            bssid_sections = re.split(r"BSSID \d+", block)
            for sec in bssid_sections[1:]:
                bssid_match = re.search(r"([0-9a-fA-F:]{17}|[0-9a-fA-F-]{17})", sec)
                sig_match = re.search(r"Signal\s*:\s*(\d+)%", sec)
                ch_match = re.search(r"Channel\s*:\s*(\d+)", sec)
                if not bssid_match:
                    continue
                bssid = normalize_bssid(bssid_match.group(1))
                # netsh signal is % not dBm; convert approx
                signal_pct = int(sig_match.group(1)) if sig_match else 50
                signal_dbm = int((signal_pct / 2) - 100)  # rough: 100%=-50, 0%=-100
                channel = int(ch_match.group(1)) if ch_match else 1
                # Parse auth/cipher from block header
                auth_m = re.search(r"Authentication\s*:\s*(.+)", block)
                enc_m = re.search(r"Encryption\s*:\s*(.+)", block)
                if auth_m:
                    auth = auth_m.group(1).strip()
                if enc_m:
                    cipher = enc_m.group(1).strip()
                # Derive encryption label
                if "open" in auth.lower():
                    encryption = "Open"
                elif "wep" in auth.lower() or "wep" in cipher.lower():
                    encryption = "WEP"
                elif "wpa" in auth.lower():
                    encryption = auth
                    if "tkip" in cipher.lower():
                        encryption = "WPA-TKIP"
                else:
                    encryption = auth or "Unknown"

                freq = 2412 if channel <= 14 else 5180
                vendor = vendor_from_bssid(bssid)
                networks.append(WiFiNetwork(
                    ssid=ssid, bssid=bssid, signal_dbm=signal_dbm,
                    channel=channel, frequency=freq,
                    encryption=encryption, cipher=cipher, auth=auth,
                    vendor=vendor
                ))
        return networks
