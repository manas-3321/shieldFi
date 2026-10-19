"""Dark theme constants for CustomTkinter.

Justification in docs/ARCHITECTURE.md — CustomTkinter chosen for:
- Pure Python, no Node/Electron
- Beginner friendly, Tkinter knowledge transfers
- Gorgeous dark mode with 1-line theme switch
"""
# Colors — dark mode, hacker / security vibe
THEME = {
    "bg": "#0f1117",           # main background (deep navy-black)
    "card_bg": "#1a1d26",      # card background
    "card_border": "#2a2e3a",
    "text_primary": "#e6e8ef",
    "text_secondary": "#9aa0b5",
    "text_muted": "#6b7280",
    "accent": "#3b82f6",        # blue for safe/interactive
    "green": "#10b981",         # safe
    "yellow": "#f59e0b",        # weak/unencrypted
    "red": "#ef4444",           # active attack
    "green_bg": "#064e3b",
    "yellow_bg": "#78350f",
    "red_bg": "#7f1d1d",
}

# Threat colors mapped
THREAT_COLORS = {
    "green":  {"fg": THEME["green"], "bg": THEME["green_bg"], "label": "SAFE", "emoji": "🛡️"},
    "yellow": {"fg": THEME["yellow"], "bg": THEME["yellow_bg"], "label": "CAUTION", "emoji": "⚠️"},
    "red":    {"fg": THEME["red"], "bg": THEME["red_bg"], "label": "DANGER", "emoji": "🚨"},
}

# Security icons (text emoji — no image assets needed)
SECURITY_ICONS = {
    "WPA3": "🔒",        # strongest
    "WPA2": "🔒",
    "WPA": "🔓",
    "WPA-TKIP": "⚠️",
    "WEP": "🔓",
    "Open": "⚠️",
    "Unknown": "❓",
}

# Signal bars
def signal_bars(dbm: int) -> str:
    if dbm >= -50:
        return "▂▃▅▆█"  # excellent
    if dbm >= -67:
        return "▂▃▅▆ "
    if dbm >= -80:
        return "▂▃▅  "
    return "▂    "

FONTS = {
    "title": ("Segoe UI", 18, "bold"),
    "subtitle": ("Segoe UI", 12),
    "body": ("Segoe UI", 11),
    "small": ("Segoe UI", 10),
    "mono": ("Consolas", 10),
}
