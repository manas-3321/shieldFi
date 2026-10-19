"""Data model for a scanned Wi-Fi network (AP)."""
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class WiFiNetwork:
    ssid: str                           # e.g. "CoffeeShop_Free"
    bssid: str                          # MAC like "AA:BB:CC:11:22:33"
    signal_dbm: int = -70               # RSSI in dBm (negative)
    channel: int = 1
    frequency: int = 2412               # MHz
    encryption: str = "Unknown"         # "Open", "WPA2-PSK", "WPA3", "WEP", "WPA-TKIP"...
    cipher: str = ""                    # "CCMP", "TKIP", "WEP"
    auth: str = ""                      # "PSK", "Enterprise", "Open"
    vendor: str = "Unknown"             # OUI lookup result
    hidden: bool = False
    connected: bool = False             # Is this the current AP?
    extra: dict = field(default_factory=dict)

    def short_encryption(self) -> str:
        e = self.encryption.lower()
        if "wpa3" in e:
            return "WPA3"
        if "wpa2" in e:
            return "WPA2"
        if "wpa" in e and "tkip" in e:
            return "WPA-TKIP"
        if "wpa" in e:
            return "WPA"
        if "wep" in e:
            return "WEP"
        if "open" in e or e in ("", "none"):
            return "Open"
        return self.encryption

    @property
    def is_open(self) -> bool:
        return self.short_encryption() == "Open"

    @property
    def is_weak(self) -> bool:
        return self.short_encryption() in ("WEP", "WPA-TKIP", "Open")
