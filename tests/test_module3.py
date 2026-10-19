"""Tests for Module 3 — Active fingerprint."""
from shieldfi.active.arp_check import check_arp_spoof
from shieldfi.active.dns_check import check_dns_hijack
from shieldfi.active.fingerprint import ActiveFingerprint

def test_arp_spoof_mock():
    r = check_arp_spoof(mock=True, mock_scenario="arp_spoof")
    assert r.is_spoof_suspected is True
    assert "DE:AD:BE" in r.gateway_mac

def test_arp_normal_mock():
    r = check_arp_spoof(mock=True, mock_scenario="normal")
    assert r.is_spoof_suspected is False

def test_dns_hijack_mock():
    r = check_dns_hijack(mock=True, mock_scenario="hijacked")
    assert r.is_hijack_suspected is True

def test_dns_normal_mock():
    r = check_dns_hijack(mock=True, mock_scenario="normal")
    assert r.is_hijack_suspected is False

def test_fingerprint_red_on_attack():
    fp = ActiveFingerprint()
    result = fp.run(mock=True, mock_scenario="all_risky")
    assert result.threat_level == "red"
    assert result.overall_safe is False

def test_fingerprint_green_normal():
    fp = ActiveFingerprint()
    result = fp.run(mock=True, mock_scenario="normal")
    assert result.threat_level == "green"
