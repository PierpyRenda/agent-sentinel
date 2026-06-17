import pytest
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
from sentinel.cli import app

runner = CliRunner()

@patch("sentinel.skills.analyzer.analyze_skill")
@patch("sentinel.skills.analyzer.analyze_mcp")
@patch("pathlib.Path.exists")
@patch("pathlib.Path.is_file")
@patch("pathlib.Path.is_dir")
@patch("pathlib.Path.resolve")
def test_skill_scan_dir(mock_resolve, mock_is_dir, mock_is_file, mock_exists, mock_mcp, mock_skill):
    mock_exists.return_value = True
    mock_is_dir.return_value = True
    mock_is_file.return_value = False

    mock_resolve.return_value = MagicMock(
        exists=lambda: True,
        is_dir=lambda: True,
        is_file=lambda: False,
        suffix="",
        glob=lambda x: []
    )

    from collections import namedtuple
    Finding = namedtuple("Finding", ["id", "label", "severity", "matches", "file"])
    f = Finding("ID1", "Label 1", "HIGH", ["match 1"], "test.js")
    mock_mcp.return_value = [f]

    result = runner.invoke(app, ["skill", "scan", "test_dir", "--json"])
    assert result.exit_code == 1

@patch("sentinel.skills.config_scanner.scan_configs")
def test_skill_scan_configs_invalid_json(mock_scan):
    mock_scan.return_value = [{"path": "config.json", "status": "invalid_json", "error": "syntax error"}]
    result = runner.invoke(app, ["skill", "scan-configs"])
    assert result.exit_code == 0

@patch("sentinel.skills.config_scanner.scan_configs")
def test_skill_scan_configs_not_found(mock_scan):
    mock_scan.return_value = [{"path": "config.json", "status": "not_found"}]
    result = runner.invoke(app, ["skill", "scan-configs"])
    assert result.exit_code == 0

@patch("sentinel.skills.config_scanner.scan_env_files")
def test_keys_scan_env_json(mock_scan_env):
    mock_scan_env.return_value = [{"path": ".env", "findings": [{"id": "SEC1", "severity": "HIGH", "label": "test", "matches": ["sec"]}]}]
    result = runner.invoke(app, ["skill", "scan-env", "--json"])
    assert result.exit_code == 0
