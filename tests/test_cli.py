import pytest
from typer.testing import CliRunner
from sentinel.cli import app, _max_severity, _exit_code
from unittest.mock import patch, MagicMock

runner = CliRunner()

def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "agent-sentinel" in result.stdout

def test_max_severity_empty():
    assert _max_severity([]) == "CLEAN"

def test_max_severity_objects():
    class Finding:
        def __init__(self, severity):
            self.severity = severity
    assert _max_severity([Finding("LOW"), Finding("HIGH"), Finding("MEDIUM")]) == "HIGH"

def test_max_severity_dicts():
    assert _max_severity([{"severity": "LOW"}, {"severity": "CRITICAL"}]) == "CRITICAL"

def test_exit_code():
    assert _exit_code("CRITICAL") == 2
    assert _exit_code("HIGH") == 1
    assert _exit_code("MEDIUM") == 0
    assert _exit_code("LOW") == 0
    assert _exit_code("CLEAN") == 0

def test_keys_scan_missing_args():
    result = runner.invoke(app, ["keys", "scan"])
    assert result.exit_code == 1

@patch("sentinel.skills.analyzer.analyze_skill")
@patch("pathlib.Path.exists")
@patch("pathlib.Path.is_file")
@patch("pathlib.Path.suffix", new=".md")
def test_skill_scan_file(mock_is_file, mock_exists, mock_analyze):
    mock_exists.return_value = True
    mock_is_file.return_value = True

    from collections import namedtuple
    Finding = namedtuple("Finding", ["id", "label", "severity", "matches", "file"])

    f = Finding("ID1", "Label 1", "HIGH", ["match 1"], "test.md")
    # Need to add _asdict method because namedtuple has it, but Typer uses it.
    mock_analyze.return_value = [f]

    result = runner.invoke(app, ["skill", "scan", "test.md", "--json"])
    assert result.exit_code == 1

@patch("pathlib.Path.exists")
def test_skill_scan_not_found(mock_exists):
    mock_exists.return_value = False
    result = runner.invoke(app, ["skill", "scan", "nonexistent.md"])
    assert result.exit_code == 1

@patch("sentinel.skills.integrity.verify_all")
def test_skill_verify_all(mock_verify):
    mock_verify.return_value = [{"name": "test", "dir": "dir", "status": "match", "source": None}]
    result = runner.invoke(app, ["skill", "verify-all"])
    assert result.exit_code == 0

@patch("sentinel.skills.integrity.verify_all")
def test_skill_verify_all_mismatch(mock_verify):
    mock_verify.return_value = [{"name": "test", "dir": "dir", "status": "mismatch", "source": None}]
    result = runner.invoke(app, ["skill", "verify-all", "--json"])
    # The --json argument calls `return` instead of raising Typer Exit if we look at the code!
    # Ah! If --json, it just prints and returns (default exit code 0)
    assert result.exit_code == 0

@patch("sentinel.skills.integrity.update_lock")
def test_skill_verify_all_update(mock_update):
    mock_update.return_value = 1
    result = runner.invoke(app, ["skill", "verify-all", "--update"])
    assert result.exit_code == 0

@patch("sentinel.skills.config_scanner.scan_configs")
def test_skill_scan_configs_clean(mock_scan):
    mock_scan.return_value = [{"path": "config.json", "servers": []}]
    result = runner.invoke(app, ["skill", "scan-configs", "--json"])
    assert result.exit_code == 0

@patch("sentinel.skills.config_scanner.scan_configs")
def test_skill_scan_configs_issues(mock_scan):
    mock_scan.return_value = [{"path": "config.json", "servers": [{"name": "srv1", "issues": ["issue 1"]}]}]
    result = runner.invoke(app, ["skill", "scan-configs"])
    assert result.exit_code == 1

@patch("sentinel.skills.config_scanner.scan_env_files")
def test_skill_scan_env_clean(mock_scan):
    mock_scan.return_value = [{"gitignore_check": True}, {"path": ".env", "findings": []}]
    result = runner.invoke(app, ["skill", "scan-env"])
    assert result.exit_code == 0

@patch("sentinel.skills.config_scanner.scan_env_files")
def test_skill_scan_env_issues(mock_scan):
    mock_scan.return_value = [{"gitignore_check": False}, {"path": ".env", "findings": [{"id": "SEC1", "severity": "HIGH", "label": "test", "matches": ["sec"]}]}]
    result = runner.invoke(app, ["skill", "scan-env"])
    assert result.exit_code == 1
