"""ShieldFi Dashboard — dark mode desktop app.

Combines: scanner + Module1 + Module2 + Module3 into one window.
Sections:
 1) Threat Level Shield (top) — Green/Yellow/Red
 2) Nearby AP list (left) — with security icons
 3) Why am I unsafe? (right/bottom) — plain English

Run: python -m shieldfi.ui.app  OR  python main.py
"""
import platform
import json
import os
from typing import List

try:
    import customtkinter as ctk
    HAS_CTK = True
except ImportError:
    HAS_CTK = False
    ctk = None
    import tkinter as tk

from .theme import THEME, THREAT_COLORS
from .components.shield import ThreatShield
from .components.ap_list import APListPanel
from .components.explain_panel import ExplainPanel

from ..scanner.mock import MockScanner
from ..scanner.models import WiFiNetwork
from ..analysis.risk_audit import PassiveRiskAuditor
from ..analysis.evil_twin import EvilTwinDetector
from ..active.fingerprint import ActiveFingerprint
from ..utils.logger import get_logger

log = get_logger()

# Try to load OS-specific scanner
def _get_os_scanner():
    system = platform.system().lower()
    try:
        if system == "windows":
            from ..scanner.windows import WindowsScanner
            s = WindowsScanner()
            if s.is_available():
                return s
        elif system == "linux":
            from ..scanner.linux import LinuxScanner
            s = LinuxScanner()
            if s.is_available():
                return s
        elif system == "darwin":
            from ..scanner.macos import MacOSScanner
            s = MacOSScanner()
            if s.is_available():
                return s
    except Exception as e:
        log.warning(f"OS scanner init failed: {e}")
    return None

def run_dashboard(mock: bool = False, mock_scenario: str = "evil_twin"):
    """Launch the GUI event loop."""
    # --- Appearance ---
    if HAS_CTK:
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        root = ctk.CTk()
        root.configure(fg_color=THEME["bg"])
    else:
        root = tk.Tk()
        root.configure(bg=THEME["bg"])

    root.title("ShieldFi — Wi-Fi Security Auditor")
    root.geometry("960x700")
    root.minsize(900, 650)

    # --- State ---
    state = {
        "mock": mock,
        "mock_scenario": mock_scenario,
        "networks": [],
        "threat_level": "green",
        "explanations": [],
    }

    # --- Load trusted networks ---
    trusted_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "config", "trusted_networks.json")
    trusted_networks = []
    if os.path.exists(trusted_path):
        try:
            with open(trusted_path) as f:
                trusted_networks = json.load(f).get("trusted_networks", [])
        except Exception:
            pass

    auditor = PassiveRiskAuditor(trusted_networks=trusted_networks)
    detector = EvilTwinDetector()
    active_checker = ActiveFingerprint()

    # --- Layout: top shield, middle two columns, bottom explain + controls ---
    if HAS_CTK:
        # Title bar
        title_frame = ctk.CTkFrame(root, fg_color="transparent")
        title_frame.pack(fill="x", padx=16, pady=(12, 0))
        ctk.CTkLabel(title_frame, text="🛡️ ShieldFi", font=("Segoe UI", 20, "bold"), text_color=THEME["text_primary"]).pack(side="left")
        ctk.CTkLabel(title_frame, text="  Lightweight Wi-Fi Auditor  •  Defensive Only", font=("Segoe UI", 11), text_color=THEME["text_muted"]).pack(side="left", padx=(10, 0))

        # Controls row
        controls = ctk.CTkFrame(root, fg_color=THEME["card_bg"], corner_radius=10, border_width=1, border_color=THEME["card_border"])
        controls.pack(fill="x", padx=16, pady=10)
        mock_var = ctk.BooleanVar(value=mock)
        scenario_var = ctk.StringVar(value=mock_scenario)

        def toggle_mock():
            state["mock"] = mock_var.get()
            do_scan()

        ctk.CTkSwitch(controls, text="Mock / Demo Mode", variable=mock_var, command=toggle_mock, font=("Segoe UI", 11)).pack(side="left", padx=12, pady=8)
        ctk.CTkLabel(controls, text="Scenario:", font=("Segoe UI", 11), text_color=THEME["text_secondary"]).pack(side="left", padx=(16, 4))
        scenario_menu = ctk.CTkOptionMenu(controls, variable=scenario_var, values=["evil_twin", "normal", "open_risk", "arp_spoof", "all_risky", "hijacked"], width=140, command=lambda _v: (state.update({"mock_scenario": _v}), do_scan()))
        scenario_menu.pack(side="left", padx=4)
        scan_btn = ctk.CTkButton(controls, text="🔍  Scan Now", width=120, fg_color=THEME["accent"], hover_color="#2563eb", command=lambda: do_scan())
        scan_btn.pack(side="right", padx=12, pady=6)
        active_btn = ctk.CTkButton(controls, text="⚡ Active Check (5s)", width=150, fg_color=THEME["card_border"], hover_color="#3a3f55", command=lambda: do_active_check())
        active_btn.pack(side="right", padx=4)

        # Main content — two columns
        main = ctk.CTkFrame(root, fg_color="transparent")
        main.pack(fill="both", expand=True, padx=16, pady=6)

        left_col = ctk.CTkFrame(main, fg_color="transparent")
        left_col.pack(side="left", fill="both", expand=True, padx=(0, 8))
        right_col = ctk.CTkFrame(main, fg_color="transparent", width=380)
        right_col.pack(side="right", fill="both", padx=(8, 0))
        right_col.pack_propagate(False)

    else:
        # Tkinter fallback layout
        title_frame = tk.Frame(root, bg=THEME["bg"])
        title_frame.pack(fill="x", padx=16, pady=(12, 0))
        tk.Label(title_frame, text="🛡️ ShieldFi", font=("Segoe UI", 20, "bold"), bg=THEME["bg"], fg=THEME["text_primary"]).pack(side="left")
        tk.Label(title_frame, text="  Lightweight Wi-Fi Auditor", font=("Segoe UI", 11), bg=THEME["bg"], fg=THEME["text_muted"]).pack(side="left")

        controls = tk.Frame(root, bg=THEME["card_bg"], highlightthickness=1, highlightbackground=THEME["card_border"])
        controls.pack(fill="x", padx=16, pady=10)
        scan_btn = tk.Button(controls, text="🔍 Scan Now", bg=THEME["accent"], fg="white", command=lambda: do_scan())
        scan_btn.pack(side="right", padx=12, pady=6)
        active_btn = tk.Button(controls, text="⚡ Active Check (5s)", bg=THEME["card_border"], fg="white", command=lambda: do_active_check())
        active_btn.pack(side="right", padx=4)

        main = tk.Frame(root, bg=THEME["bg"])
        main.pack(fill="both", expand=True, padx=16, pady=6)
        left_col = tk.Frame(main, bg=THEME["bg"])
        left_col.pack(side="left", fill="both", expand=True, padx=(0, 8))
        right_col = tk.Frame(main, bg=THEME["bg"], width=380)
        right_col.pack(side="right", fill="both", padx=(8, 0))
        right_col.pack_propagate(False)

    # --- Widgets inside columns ---
    shield = ThreatShield(right_col, size=160)
    shield.pack(fill="x", padx=4, pady=4)

    ap_panel = APListPanel(left_col)
    ap_panel.pack(fill="both", expand=True, padx=4, pady=4)

    explain = ExplainPanel(right_col)
    explain.pack(fill="both", expand=True, padx=4, pady=8)

    # Status bar
    if HAS_CTK:
        status = ctk.CTkLabel(root, text="Ready. Click 'Scan Now' — or enable Mock Mode for a demo without Wi-Fi.", font=("Segoe UI", 10), text_color=THEME["text_muted"], anchor="w")
        status.pack(fill="x", padx=16, pady=(4, 10))
    else:
        status = tk.Label(root, text="Ready.", font=("Segoe UI", 10), bg=THEME["bg"], fg=THEME["text_muted"], anchor="w")
        status.pack(fill="x", padx=16, pady=(4, 10))

    # --- Logic: do_scan ---
    def do_scan():
        mock_enabled = state["mock"] if HAS_CTK else mock
        scenario = state.get("mock_scenario", mock_scenario) if HAS_CTK else mock_scenario

        status.configure(text=f"Scanning... (mode={'MOCK:'+scenario if mock_enabled else 'LIVE OS'})")

        # Choose scanner
        if mock_enabled:
            scanner = MockScanner(scenario=scenario)
        else:
            scanner = _get_os_scanner()
            if scanner is None:
                # No OS scanner available (e.g., headless Linux without nmcli) -> fallback to mock with warning
                status.configure(text="No OS scanner available — switching to Mock mode for demo. Install nmcli/netsh/airport for live scans.")
                explain.set_explanations([
                    "No Wi-Fi adapter or scan tool found on this system.",
                    "Fix: On Linux, install NetworkManager (`sudo apt install network-manager`) and ensure `nmcli` is available.",
                    "On Windows, `netsh` should be available by default — try running as normal user (no admin needed).",
                    "On macOS, ensure `/System/Library/PrivateFrameworks/Apple80211.framework/Resources/airport` exists.",
                    "For now, enable Mock Mode to see a full demo."
                ], threat_level="yellow")
                scanner = MockScanner(scenario="evil_twin")
            else:
                log.info(f"Using OS scanner: {scanner.name}")

        try:
            networks = scanner.scan()
        except Exception as e:
            log.warning(f"Scan error: {e}")
            networks = []
            status.configure(text=f"Scan failed: {e}")

        state["networks"] = networks
        state["threat_level"] = "green"

        if not networks:
            shield.set_level("yellow", "No networks found")
            explain.set_explanations(["No networks returned. Check adapter / permissions, or use Mock mode."], "yellow")
            status.configure(text="Scan returned 0 networks.")
            return

        # Module 1 — Passive audit
        findings = auditor.audit(networks)
        level_m1 = auditor.overall_level(findings)

        # Module 2 — Evil Twin
        detector.update_history(networks)
        evil_results = detector.analyze(networks)
        evil_score = detector.global_suspicion_score(evil_results)

        # Decide final threat level (highest wins)
        if evil_score >= 60:
            final_level = "red"
            subtitle = f"Evil Twin likely! Score {evil_score}/100"
        elif evil_score >= 30:
            final_level = "yellow" if level_m1 != "red" else "red"
            subtitle = f"Suspicious network (score {evil_score}/100)"
        elif findings:
            # Module1 yellow (open/WEP)
            final_level = "yellow"
            subtitle = auditor.plain_summary(findings)
        else:
            final_level = "green"
            subtitle = f"Scanned {len(networks)} networks — all secure"

        state["threat_level"] = final_level
        shield.set_level(final_level, subtitle)

        # Build highlights for AP list (flagged BSSIDs)
        highlights = {}
        for r in evil_results:
            for b in r.related_bssids:
                highlights[b] = r.score
        # Also flag open/WEP directly
        for f in findings:
            if f.severity in ("critical", "high"):
                highlights[f.network.bssid] = highlights.get(f.network.bssid, f.score)

        ap_panel.update_networks(networks, highlights=highlights)

        # Build explanations
        explanations: List[str] = []
        if findings:
            for f in findings:
                explanations.append(f"[{f.network.ssid} — {f.network.bssid}] {f.message} (Encryption: {f.network.encryption}, Vendor: {f.network.vendor})")
        if evil_results:
            explanations.extend(detector.plain_explanations(evil_results))
            # Add graph insight
            for r in evil_results:
                gi = r.graph_insights
                if gi.get("suspicious_pairs", 0) > 0:
                    explanations.append(f"Network graph: {gi['suspicious_pairs']} suspicious SSID relationships, density {gi.get('density', 0):.2f}. Most connected AP: {gi.get('most_connected')}")
        if not explanations:
            explanations = [f"Scanned {len(networks)} networks — no risks found. You're on a reasonably secure setup."]

        explain.set_explanations(explanations, threat_level=final_level)
        status.configure(text=f"Scan done: {len(networks)} APs  •  Threat: {final_level.upper()}  •  Findings: {len(findings)}  •  EvilTwin score: {evil_score}/100  •  Mode: {'MOCK:'+scenario if mock_enabled else 'LIVE'}")

    def do_active_check():
        status.configure(text="Running 5-second active check (gateway + DNS)...")
        # Disable button briefly
        try:
            active_btn.configure(state="disabled", text="⏳ Checking...")
        except Exception:
            pass

        def run():
            mock_enabled = state["mock"] if HAS_CTK else mock
            scenario = state.get("mock_scenario", mock_scenario) if HAS_CTK else mock_scenario
            result = active_checker.run(mock=mock_enabled, mock_scenario=scenario)
            # Update UI on main thread
            def update_ui():
                if result.threat_level == "red":
                    shield.set_level("red", "Active attack detected!")
                # Merge explanations
                new_lines = result.plain_explanations
                # Keep existing + add active
                existing = explain.items if hasattr(explain, "items") else []
                combined = existing + ["--- Active Check (5s) ---"] + new_lines + [f"Duration: {result.duration_sec}s | {result.summary}"]
                explain.set_explanations(combined, threat_level=result.threat_level if result.threat_level == "red" else state["threat_level"])
                status.configure(text=f"Active check done in {result.duration_sec}s: {result.summary} | Threat: {result.threat_level.upper()}")
                try:
                    active_btn.configure(state="normal", text="⚡ Active Check (5s)")
                except Exception:
                    pass
            root.after(0, update_ui)

        # Run in background thread so UI doesn't freeze
        import threading
        threading.Thread(target=run, daemon=True).start()

    # Auto-scan on launch
    root.after(500, do_scan)

    # --- Run ---
    if HAS_CTK:
        root.mainloop()
    else:
        root.mainloop()

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="ShieldFi Dashboard")
    p.add_argument("--mock", action="store_true", help="Start in mock/demo mode")
    p.add_argument("--scenario", default="evil_twin", help="Mock scenario")
    args = p.parse_args()
    run_dashboard(mock=args.mock, mock_scenario=args.scenario)
