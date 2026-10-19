"""OUI -> Vendor lookup (tiny curated DB for demo).

WHY: Real OUI list is 30k+ entries. For hackathon we bundle ~40 common vendors.
For production, download https://standards-oui.ieee.org/oui/oui.csv
"""

# OUI is first 3 octets of BSSID, e.g. AA:BB:CC -> Vendor
OUI_DB: dict[str, str] = {
    "00:1A:2B": "Cisco",
    "00:1A:2C": "Cisco",
    "3C:08:F6": "Cisco Meraki",
    "F8:0B:D0": "Cisco",
    "AA:BB:CC": "TP-Link",          # mock / demo
    "A4:CF:12": "TP-Link",
    "50:C7:BF": "TP-Link",
    "00:1D:0F": "TP-Link",
    "10:FE:ED": "Netgear",
    "28:80:88": "Netgear",
    "9C:3D:CF": "Netgear",
    "DC:A6:32": "Raspberry Pi",
    "B8:27:EB": "Raspberry Pi",
    "3C:22:FB": "Apple",
    "A4:5E:60": "Apple",
    "F0:18:98": "Apple",
    "FC:A6:21": "TP-Link / EvilCap", # used in evil-twin mock to show unknown
    "DE:AD:BE": "Unknown / Spoofed", # locally administered -> suspicious
    "02:00:00": "Locally Administered",
    "12:34:56": "Unknown / Lab Device",
    "00:0C:43": "Ralink",
    "00:23:CD": "Realtek",
    "FC:EC:DA": "Ubiquiti",
    "78:8A:20": "Ubiquiti",
    "24:5A:4C": "Ubiquiti",
    "00:15:6D": "Ubiquiti",
    "E0:63:DA": "HUAWEI",
    "AC:CF:23": "HUAWEI",
    "14:CC:20": "HUAWEI",
    "08:19:A6": "HUAWEI",
    "D8:47:32": "Xiaomi",
    "64:64:4A": "Xiaomi",
    "00:1E:42": "Intel",
    "3C:FD:FE": "Intel",
    "18:3D:A2": "Intel",
    "5C:CF:7F": "Espressif",
    "24:0A:C4": "Espressif",
    "30:AE:A4": "Espressif",
}

def vendor_from_bssid(bssid: str) -> str:
    """Return vendor name from BSSID's OUI (first 3 octets)."""
    if not bssid:
        return "Unknown"
    bssid = bssid.strip().upper().replace("-", ":")
    parts = bssid.split(":")
    if len(parts) < 3:
        return "Unknown"
    oui = ":".join(parts[:3])
    if oui in OUI_DB:
        return OUI_DB[oui]
    # Check if locally administered (2nd bit of first octet)
    try:
        first_octet = int(parts[0], 16)
        if first_octet & 0x02:
            return "Unknown / Locally Administered (Suspicious)"
    except ValueError:
        pass
    return "Unknown"

def is_suspicious_vendor(vendor: str) -> bool:
    """Flag vendors that often indicate spoofed / software AP."""
    v = vendor.lower()
    return any(k in v for k in ["unknown", "locally administered", "espressif", "raspberry", "spoofed"])
