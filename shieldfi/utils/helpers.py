"""Small helpers: normalize BSSID, channel helpers, signal helpers."""
import re

def normalize_bssid(bssid: str) -> str:
    """Normalize BSSID to uppercase AA:BB:CC:DD:EE:FF form."""
    if not bssid:
        return ""
    bssid = bssid.strip().upper().replace("-", ":").replace(".", ":")
    # handle Cisco style aabb.ccdd.eeff
    if "." in bssid:
        bssid = bssid.replace(".", "")
        bssid = ":".join(bssid[i:i+2] for i in range(0, 12, 2))
    # ensure 6 octets
    parts = [p for p in re.split(r"[:\s]", bssid) if p]
    # if no colons but 12 hex chars
    if len(parts) == 1 and len(parts[0]) == 12:
        parts = [parts[0][i:i+2] for i in range(0, 12, 2)]
    return ":".join(p.zfill(2) for p in parts[:6])

def signal_quality(signal_dbm: int) -> str:
    """Human friendly signal strength."""
    if signal_dbm >= -50:
        return "Excellent"
    if signal_dbm >= -67:
        return "Good"
    if signal_dbm >= -80:
        return "Weak"
    return "Poor"

def channel_to_freq(channel: int) -> int:
    """Approximate center frequency MHz for 2.4/5 GHz."""
    if 1 <= channel <= 14:
        return 2407 + channel * 5
    # 5 GHz (simplified)
    return 5000 + channel * 5
