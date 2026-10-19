"""Tests for Module 2 — Evil Twin Detector."""
from shieldfi.scanner.mock import MockScanner
from shieldfi.analysis.evil_twin import EvilTwinDetector

def test_evil_twin_detected():
    scanner = MockScanner(scenario="evil_twin")
    nets = scanner.scan()
    d = EvilTwinDetector()
    d.update_history(nets)
    results = d.analyze(nets)
    assert len(results) >= 1, "Should detect evil twin"
    assert any(r.score >= 60 for r in results), "Evil twin should score >=60 (red)"
    # Top should be one of the evil-twin SSIDs (Campus_WiFi scores 100 in this scenario)
    top = results[0]
    assert top.ssid in ("CoffeeShop_Free", "Campus_WiFi")
    assert any(rs.code == "duplicate_ssid" for rs in top.reasons)

def test_normal_no_evil_twin():
    scanner = MockScanner(scenario="normal")
    nets = scanner.scan()
    d = EvilTwinDetector()
    results = d.analyze(nets)
    assert len(results) == 0, "Normal scenario should have no evil twin flags"

def test_vendor_change():
    scanner = MockScanner(scenario="evil_twin")
    nets = scanner.scan()
    d = EvilTwinDetector()
    results = d.analyze(nets)
    # Campus_WiFi with TKIP + unknown vendor should trigger vendor_change
    assert any(any(rs.code == "vendor_change" for rs in r.reasons) for r in results)
