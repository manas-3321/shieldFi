"""Threat Level Shield — animated indicator (Green/Yellow/Red)."""
import math

try:
    import customtkinter as ctk
    HAS_CTK = True
except ImportError:
    HAS_CTK = False
    ctk = None

from ..theme import THEME, THREAT_COLORS

class ThreatShield:
    """Canvas-based shield widget. Works with CustomTkinter or plain Tkinter fallback."""

    def __init__(self, parent, size: int = 160):
        self.parent = parent
        self.size = size
        self.level = "green"
        self.pulse_phase = 0
        self._after_id = None

        if HAS_CTK:
            self.frame = ctk.CTkFrame(parent, fg_color=THEME["card_bg"], corner_radius=16, border_width=1, border_color=THEME["card_border"])
            self.canvas = ctk.CTkCanvas(self.frame, width=size, height=size, bg=THEME["card_bg"], highlightthickness=0)
            self.canvas.pack(pady=(12, 4))
            self.label = ctk.CTkLabel(self.frame, text="SAFE", font=("Segoe UI", 16, "bold"), text_color=THREAT_COLORS["green"]["fg"])
            self.label.pack()
            self.subtitle = ctk.CTkLabel(self.frame, text="No threats detected", font=("Segoe UI", 11), text_color=THEME["text_secondary"])
            self.subtitle.pack(pady=(2, 12))
        else:
            import tkinter as tk
            self.frame = tk.Frame(parent, bg=THEME["card_bg"], highlightthickness=1, highlightbackground=THEME["card_border"])
            self.canvas = tk.Canvas(self.frame, width=size, height=size, bg=THEME["card_bg"], highlightthickness=0)
            self.canvas.pack(pady=(12, 4))
            self.label = tk.Label(self.frame, text="SAFE", font=("Segoe UI", 16, "bold"), bg=THEME["card_bg"], fg=THREAT_COLORS["green"]["fg"])
            self.label.pack()
            self.subtitle = tk.Label(self.frame, text="No threats detected", font=("Segoe UI", 11), bg=THEME["card_bg"], fg=THEME["text_secondary"])
            self.subtitle.pack(pady=(2, 12))

        self._draw_shield("green")

    def pack(self, **kwargs):
        self.frame.pack(**kwargs)

    def grid(self, **kwargs):
        self.frame.grid(**kwargs)

    def set_level(self, level: str, subtitle: str = None):
        """level: green|yellow|red"""
        if level not in THREAT_COLORS:
            level = "green"
        self.level = level
        info = THREAT_COLORS[level]
        self.label.configure(text=f"{info['emoji']}  {info['label']}", text_color=info["fg"])
        if subtitle:
            self.subtitle.configure(text=subtitle)
        else:
            defaults = {"green": "No threats detected", "yellow": "Weak or unencrypted network", "red": "Active attack suspected!"}
            self.subtitle.configure(text=defaults[level])
        self._draw_shield(level)
        # Pulse animation for red
        if level == "red":
            self._pulse()
        else:
            self._stop_pulse()

    def _draw_shield(self, level: str):
        c = self.canvas
        c.delete("all")
        info = THREAT_COLORS[level]
        cx, cy = self.size // 2, self.size // 2
        r = self.size // 2 - 10

        # Outer glow (concentric circles)
        for i in range(3):
            alpha_r = r - i * 6
            shade = info["bg"] if i == 0 else THEME["card_bg"]
            # Simulate glow with multiple ovals
            c.create_oval(cx - alpha_r, cy - alpha_r, cx + alpha_r, cy + alpha_r,
                          fill=shade, outline="", width=0)

        # Main shield shape — simple circle with lock icon text
        c.create_oval(cx - r + 12, cy - r + 12, cx + r - 12, cy + r - 12,
                      fill=info["fg"], outline="", width=0)
        # Inner darker circle for depth
        c.create_oval(cx - r + 22, cy - r + 22, cx + r - 22, cy + r - 22,
                      fill=THEME["card_bg"], outline="", width=0)
        # Emoji icon in center (large text)
        c.create_text(cx, cy, text=info["emoji"], font=("Segoe UI Emoji", 42), fill=info["fg"])

    def _pulse(self):
        """Simple pulse: vary size slightly every 500ms."""
        if self.level != "red":
            return
        self.pulse_phase = (self.pulse_phase + 1) % 4
        # Re-draw with slightly larger radius on even phases
        extra = 4 if self.pulse_phase % 2 == 0 else 0
        # We do minimal animation via canvas scaling effect
        try:
            after_ms = 600
            if HAS_CTK:
                self._after_id = self.frame.after(after_ms, self._pulse)
            else:
                self._after_id = self.frame.after(after_ms, self._pulse)
        except Exception:
            pass

    def _stop_pulse(self):
        if self._after_id:
            try:
                self.frame.after_cancel(self._after_id)
            except Exception:
                pass
            self._after_id = None
