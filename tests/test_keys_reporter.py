import pytest
from sentinel.keys.reporter import print_banner, print_key_info, print_scan_result, print_report, _sanitize_for_output
from pathlib import Path

def test_print_banner():
    print_banner()

def test_print_key_info():
    print_key_info("sk-123", "openai", True, "Test hint")

def test_print_scan_result():
    print_scan_result("github", True, {"url": "https://github.com"})
    print_scan_result("github", False, {})

def test_print_report():
    print_report({"scans": {"github": {"found": True, "summary": "Found in test repo"}}, "compromised": True})
    print_report({"scans": {}})

def test_sanitize_for_output():
    data = {"key": "secret_key", "valid": True, "token": "test_token"}
    sanitized = _sanitize_for_output(data)
    assert sanitized["key"] == "REDACTED"
    assert sanitized["token"] == "REDACTED"
    assert sanitized["valid"] is True
