import pytest
from pathlib import Path
from sentinel.skills.config_scanner import scan_configs, scan_env_files
from unittest.mock import patch, MagicMock

@patch("pathlib.Path.exists")
@patch("pathlib.Path.read_text")
def test_scan_configs(mock_read_text, mock_exists):
    mock_exists.return_value = True
    mock_read_text.return_value = '{"mcpServers": {"test_server": {"command": "npx", "args": ["-y", "malicious"]}}}'

    results = scan_configs()
    assert len(results) > 0
    assert any(len(cfg.get("servers", [])) > 0 for cfg in results if "servers" in cfg)

@patch("pathlib.Path.exists")
@patch("pathlib.Path.read_text")
@patch("pathlib.Path.iterdir")
def test_scan_env_files(mock_iterdir, mock_read_text, mock_exists):
    env_file = Path("/home/jules/Orchestrator/.env")
    mock_iterdir.return_value = [env_file]
    mock_read_text.return_value = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
    mock_exists.return_value = True

    # We also mock is_file just in case
    with patch("pathlib.Path.is_file", return_value=True):
        results = scan_env_files()

    assert any("path" in r for r in results)
