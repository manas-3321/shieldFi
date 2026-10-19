"""Nearby AP list with security icons."""
try:
    import customtkinter as ctk
    HAS_CTK = True
except ImportError:
    HAS_CTK = False
    ctk = None

from ...scanner.models import WiFiNetwork
from ..theme import THEME, SECURITY_ICONS, signal_bars

class APListPanel:
    """Scrollable list of APs — each row shows SSID, BSSID, signal, channel, encryption icon."""

    def __init__(self, parent):
        self.parent = parent
        self.networks: list[WiFiNetwork] = []

        if HAS_CTK:
            self.frame = ctk.CTkFrame(parent, fg_color=THEME["card_bg"], corner_radius=12, border_width=1, border_color=THEME["card_border"])
            self.header = ctk.CTkLabel(self.frame, text="📡  Nearby Networks", font=("Segoe UI", 13, "bold"), text_color=THEME["text_primary"], anchor="w")
            self.header.pack(fill="x", padx=12, pady=(10, 4))
            self.scroll = ctk.CTkScrollableFrame(self.frame, fg_color=THEME["card_bg"], height=320)
            self.scroll.pack(fill="both", expand=True, padx=8, pady=8)
        else:
            import tkinter as tk
            self.frame = tk.Frame(parent, bg=THEME["card_bg"], highlightthickness=1, highlightbackground=THEME["card_border"])
            self.header = tk.Label(self.frame, text="📡  Nearby Networks", font=("Segoe UI", 13, "bold"), bg=THEME["card_bg"], fg=THEME["text_primary"], anchor="w")
            self.header.pack(fill="x", padx=12, pady=(10, 4))
            self.scroll = tk.Frame(self.frame, bg=THEME["card_bg"])
            self.scroll.pack(fill="both", expand=True, padx=8, pady=8)

    def pack(self, **kwargs):
        self.frame.pack(**kwargs)

    def grid(self, **kwargs):
        self.frame.grid(**kwargs)

    def update_networks(self, networks: list[WiFiNetwork], highlights: dict = None):
        """highlights: {bssid: reason} for evil twin flagged BSSIDs."""
        self.networks = networks
        highlights = highlights or {}

        # Clear previous rows
        for child in self.scroll.winfo_children():
            child.destroy()

        if not networks:
            self._add_empty("No networks found. Try Mock mode or check Wi-Fi adapter.")
            return

        # Sort by signal strength (strongest first)
        networks_sorted = sorted(networks, key=lambda n: n.signal_dbm, reverse=True)

        for net in networks_sorted:
            self._add_row(net, is_flagged=net.bssid in highlights, flag_reason=highlights.get(net.bssid, ""))

    def _add_empty(self, msg: str):
        if HAS_CTK:
            lbl = ctk.CTkLabel(self.scroll, text=msg, font=("Segoe UI", 11), text_color=THEME["text_muted"], wraplength=380, justify="left")
            lbl.pack(fill="x", padx=8, pady=8)
        else:
            import tkinter as tk
            lbl = tk.Label(self.scroll, text=msg, font=("Segoe UI", 11), bg=THEME["card_bg"], fg=THEME["text_muted"], wraplength=380, justify="left")
            lbl.pack(fill="x", padx=8, pady=8)

    def _add_row(self, net: WiFiNetwork, is_flagged: bool = False, flag_reason: str = ""):
        enc = net.short_encryption()
        icon = SECURITY_ICONS.get(enc, "❓")
        signal = signal_bars(net.signal_dbm)

        # Color by risk
        if enc in ("Open", "WEP", "WPA-TKIP"):
            enc_color = THEME["red"]
            enc_bg = THEME["red_bg"]
        elif enc in ("WPA", "WPA2"):
            enc_color = THEME["yellow"]
            enc_bg = THEME["yellow_bg"]
        else:
            enc_color = THEME["green"]
            enc_bg = THEME["green_bg"]

        # Flagged (evil twin) overrides
        if is_flagged:
            row_bg = THEME["red_bg"]
            border_color = THEME["red"]
        else:
            row_bg = THEME["card_bg"]
            border_color = THEME["card_border"]

        if HAS_CTK:
            row = ctk.CTkFrame(self.scroll, fg_color=row_bg, corner_radius=10, border_width=1, border_color=border_color)
            row.pack(fill="x", padx=4, pady=4)

            top = ctk.CTkFrame(row, fg_color="transparent")
            top.pack(fill="x", padx=10, pady=(8, 2))
            ctk.CTkLabel(top, text=f"{icon}  {net.ssid}", font=("Segoe UI", 12, "bold"), text_color=THEME["text_primary"]).pack(side="left")
            ctk.CTkLabel(top, text=f"{signal}  {net.signal_dbm} dBm", font=("Consolas", 10), text_color=THEME["text_secondary"]).pack(side="right")

            mid = ctk.CTkFrame(row, fg_color="transparent")
            mid.pack(fill="x", padx=10, pady=2)
            ctk.CTkLabel(mid, text=f"{net.bssid}  •  {net.vendor}", font=("Consolas", 10), text_color=THEME["text_muted"]).pack(side="left")

            bot = ctk.CTkFrame(row, fg_color="transparent")
            bot.pack(fill="x", padx=10, pady=(2, 8))
            badge = ctk.CTkLabel(bot, text=f" {enc} ", font=("Segoe UI", 10, "bold"), text_color=enc_color, fg_color=enc_bg, corner_radius=6)
            badge.pack(side="left", padx=(0, 6))
            ctk.CTkLabel(bot, text=f"Ch {net.channel}  •  {net.frequency} MHz", font=("Segoe UI", 10), text_color=THEME["text_secondary"]).pack(side="left")
            if is_flagged:
                ctk.CTkLabel(bot, text="⚠️ FLAGGED", font=("Segoe UI", 9, "bold"), text_color=THEME["red"], fg_color=THEME["red_bg"], corner_radius=6).pack(side="right")
        else:
            import tkinter as tk
            row = tk.Frame(self.scroll, bg=row_bg, highlightthickness=1, highlightbackground=border_color)
            row.pack(fill="x", padx=4, pady=4)
            tk.Label(row, text=f"{icon}  {net.ssid}  {signal} {net.signal_dbm} dBm", font=("Segoe UI", 11, "bold"), bg=row_bg, fg=THEME["text_primary"]).pack(anchor="w", padx=10, pady=2)
            tk.Label(row, text=f"{net.bssid} • {net.vendor} • Ch{net.channel} • {enc}", font=("Consolas", 9), bg=row_bg, fg=THEME["text_muted"]).pack(anchor="w", padx=10)
            if is_flagged:
                tk.Label(row, text="⚠️ FLAGGED", font=("Segoe UI", 9, "bold"), bg=THEME["red_bg"], fg=THEME["red"]).pack(anchor="w", padx=10, pady=2)
