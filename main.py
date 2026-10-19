#!/usr/bin/env python3
"""ShieldFi launcher — choose CLI scan or GUI dashboard.

Usage:
  python main.py                  # Launch GUI (auto-detect OS, fallback to mock)
  python main.py --mock           # GUI in mock mode
  python main.py --mock --scenario all_risky
  python main.py --cli            # Text-only scan (no GUI, for servers/headless)
  python main.py --cli --mock --scenario evil_twin

WHY: One entry point for both modes — beginner friendly.
"""
import argparse
import json
import os
import sys

def cli_mode(mock: bool, scenario: str):
    """Headless scan — prints results to terminal (no GUI needed)."""
    print("🛡️ ShieldFi — CLI Scan")
    print(f"Mode: {'MOCK ('+scenario+')' if mock else 'LIVE OS'}")
    print("-" * 60)

    # Pick scanner
    if mock:
        from shieldfi.scanner.mock import MockScanner
        scanner = MockScanner(scenario=scenario)
    else:
        # Auto-detect OS scanner
        import platform
        system = platform.system().lower()
        scanner = None
        try:
            if system == "windows":
                from shieldfi.scanner.windows import WindowsScanner
                s = WindowsScanner()
                if s.is_available():
                    scanner = s
            elif system == "linux":
                from shieldfi.scanner.linux import LinuxScanner
                s = LinuxScanner()
                if s.is_available():
                    scanner = s
            elif system == "darwin":
                from shieldfi.scanner.macos import MacOSScanner
                s = MacOSScanner()
                if s.is_available():
                    scanner = s
        except Exception as e:
            print(f"OS scanner error: {e}")
        if scanner is None:
            print("⚠️ No OS scanner available — falling back to MOCK (evil_twin) for demo.")
            from shieldfi.scanner.mock import MockScanner
            scanner = MockScanner(scenario="evil_twin")

    networks = scanner.scan()
    print(f"Found {len(networks)} networks:\n")
    for n in networks:
        print(f"  {n.ssid:20s}  {n.bssid}  {n.signal_dbm:4d} dBm  Ch{n.channel:2d}  {n.short_encryption():10s}  {n.vendor}")

    # Module 1
    trusted_path = os.path.join("config", "trusted_networks.json")
    trusted = []
    if os.path.exists(trusted_path):
        with open(trusted_path) as f:
            trusted = json.load(f).get("trusted_networks", [])
    from shieldfi.analysis.risk_audit import PassiveRiskAuditor
    auditor = PassiveRiskAuditor(trusted_networks=trusted)
    findings = auditor.audit(networks)
    print("\n--- Module 1: Passive Risk Audit ---")
    if not findings:
        print("✅ No open/WEP/TKIP or mimicry found.")
    else:
        for fl in findings:
            print(f"  [{fl.severity.upper():8s}] {fl.risk:10s} {fl.network.ssid} ({fl.network.bssid}) — {fl.message[:90]}...")

    # Module 2
    from shieldfi.analysis.evil_twin import EvilTwinDetector
    detector = EvilTwinDetector()
    detector.update_history(networks)
    evil_results = detector.analyze(networks)
    print("\n--- Module 2: Evil Twin Detector ---")
    if not evil_results:
        print("✅ No evil twin signs. Score 0/100.")
    else:
        for r in evil_results:
            print(f"  [{r.level.upper():18s}] {r.ssid:20s} Score {r.score}/100")
            for rs in r.reasons:
                print(f"      • {rs.message} (evidence: {rs.evidence}) [{rs.weight}pts]")
        print(f"\n  Graph insights: {evil_results[0].graph_insights}")

    # Module 3
    from shieldfi.active.fingerprint import ActiveFingerprint
    print("\n--- Module 3: Active Fingerprint (5s) ---")
    checker = ActiveFingerprint()
    active = checker.run(mock=mock, mock_scenario=scenario)
    print(f"  Threat level: {active.threat_level.upper()}")
    print(f"  Summary: {active.summary}")
    for l in active.plain_explanations:
        print(f"    • {l}")
    print(f"  Duration: {active.duration_sec}s")

    # Overall
    final = "GREEN (Safe)" if active.threat_level == "green" and not findings and not evil_results else \
            "RED (Active Attack)" if active.threat_level == "red" or any(r.score >= 60 for r in evil_results) else \
            "YELLOW (Caution)"
    print(f"\n🛡️ Overall Threat: {final}")

def main():
    ap = argparse.ArgumentParser(description="ShieldFi — Wi-Fi Security Auditor")
    ap.add_argument("--mock", action="store_true", help="Use mock/demo data (no Wi-Fi needed)")
    ap.add_argument("--scenario", default="evil_twin", choices=["normal","evil_twin","open_risk","arp_spoof","all_risky","hijacked"], help="Mock scenario")
    ap.add_argument("--cli", action="store_true", help="Run headless CLI scan instead of GUI")
    args = ap.parse_args()

    if args.cli:
        cli_mode(mock=args.mock, scenario=args.scenario)
    else:
        # GUI
        try:
            from shieldfi.ui.app import run_dashboard
            run_dashboard(mock=args.mock, mock_scenario=args.scenario)
        except Exception as e:
            print(f"GUI failed to launch: {e}")
            print("Falling back to CLI mode...")
            cli_mode(mock=True, scenario=args.scenario)

if __name__ == "__main__":
    main()
