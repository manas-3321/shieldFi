"""Tests for Module 1 — Passive Risk Audit."""
from shieldfi.scanner.mock import MockScanner
from shieldfi.analysis.risk_audit import PassiveRiskAuditor

def test_open_flagged():
    scanner = MockScanner(scenario="open_risk")
    nets = scanner.scan()
    auditor = PassiveRiskAuditor()
    findings = auditor.audit(nets)
    assert any(f.risk == "OPEN" for f in findings), "Should flag open networks"

def test_mimicry_flagged():
    scanner = MockScanner(scenario="evil_twin")
    nets = scanner.scan()
    # Trust Campus_WiFi as Cisco — mimicry should trigger for the fake 12:34:56 one
    trusted = [{"ssid": "Campus_WiFi", "bssid": "00:1A:2B:AA:BB:CC", "vendor": "Cisco"}]
    auditor = PassiveRiskAuditor(trusted_networks=trusted)
    findings = auditor.audit(nets)
    assert any(f.risk == "MIMICRY" for f in findings), "Should flag SSID mimicry"

def test_no_false_positive_for_wep():
    # Normal scenario has WEP OldRouter — should flag WEP
    scanner = MockScanner(scenario="normal")
    nets = [n for n in scanner.scan() if n.short_encryption() == "WPA2"]
    auditor = PassiveRiskAuditor()
    findings = auditor.audit(nets)
    assert not any(f.risk == "WEP" for f in findings), "WPA2-only should not flag WEP"
