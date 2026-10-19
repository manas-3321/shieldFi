"""Why am I unsafe? — plain-English explanations."""
try:
    import customtkinter as ctk
    HAS_CTK = True
except ImportError:
    HAS_CTK = False
    ctk = None

from ..theme import THEME

class ExplainPanel:
    """Displays human-readable reasons for threat level."""

    def __init__(self, parent):
        if HAS_CTK:
            self.frame = ctk.CTkFrame(parent, fg_color=THEME["card_bg"], corner_radius=12, border_width=1, border_color=THEME["card_border"])
            self.header = ctk.CTkLabel(self.frame, text="💡  Why am I unsafe?", font=("Segoe UI", 13, "bold"), text_color=THEME["text_primary"], anchor="w")
            self.header.pack(fill="x", padx=12, pady=(10, 4))
            self.scroll = ctk.CTkScrollableFrame(self.frame, fg_color=THEME["card_bg"], height=200)
            self.scroll.pack(fill="both", expand=True, padx=8, pady=8)
        else:
            import tkinter as tk
            self.frame = tk.Frame(parent, bg=THEME["card_bg"], highlightthickness=1, highlightbackground=THEME["card_border"])
            self.header = tk.Label(self.frame, text="💡  Why am I unsafe?", font=("Segoe UI", 13, "bold"), bg=THEME["card_bg"], fg=THEME["text_primary"], anchor="w")
            self.header.pack(fill="x", padx=12, pady=(10, 4))
            self.scroll = tk.Frame(self.frame, bg=THEME["card_bg"])
            self.scroll.pack(fill="both", expand=True, padx=8, pady=8)

        self.items: list[str] = []

    def pack(self, **kwargs):
        self.frame.pack(**kwargs)

    def grid(self, **kwargs):
        self.frame.grid(**kwargs)

    def set_explanations(self, lines: list[str], threat_level: str = "green"):
        # Clear
        for child in self.scroll.winfo_children():
            child.destroy()

        if not lines:
            lines = ["All checks passed — you're on a safe network!"]

        # Color banner based on threat
        banner_colors = {"green": THEME["green"], "yellow": THEME["yellow"], "red": THEME["red"]}
        banner_bg = {"green": THEME["green_bg"], "yellow": THEME["yellow_bg"], "red": THEME["red_bg"]}

        if HAS_CTK:
            for line in lines:
                row = ctk.CTkFrame(self.scroll, fg_color=THEME["bg"], corner_radius=8)
                row.pack(fill="x", padx=4, pady=3)
                # Left colored bar
                bar = ctk.CTkFrame(row, fg_color=banner_colors.get(threat_level, THEME["green"]), width=4, corner_radius=2)
                bar.pack(side="left", fill="y", padx=(6, 0), pady=6)
                lbl = ctk.CTkLabel(row, text=line, font=("Segoe UI", 10), text_color=THEME["text_primary"], wraplength=360, justify="left", anchor="w")
                lbl.pack(side="left", fill="x", expand=True, padx=8, pady=8)
        else:
            import tkinter as tk
            for line in lines:
                lbl = tk.Label(self.scroll, text="• " + line, font=("Segoe UI", 10), bg=THEME["bg"], fg=THEME["text_primary"], wraplength=360, justify="left", anchor="w")
                lbl.pack(fill="x", padx=8, pady=3, anchor="w")

        self.items = lines
