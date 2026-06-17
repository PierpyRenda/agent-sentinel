import pytest
from unittest.mock import patch
from sentinel.skills.integrity import verify_all, update_lock, _hash_file
from pathlib import Path
import json

@patch("sentinel.skills.integrity.all_skill_dirs")
def test_verify_all_empty(mock_all_dirs):
    mock_all_dirs.return_value = []
    results = verify_all()
    assert results == []

@patch("sentinel.skills.integrity.all_skill_dirs")
@patch("pathlib.Path.exists")
@patch("pathlib.Path.read_text")
@patch("sentinel.skills.integrity.compute_hash")
def test_update_lock(mock_compute, mock_read_text, mock_exists, mock_all_dirs):
    mock_all_dirs.return_value = [(Path("/tmp/claude/.claude/skills"), Path("/tmp/claude/.claude/skills/skill1"))]
    mock_exists.return_value = True
    mock_read_text.return_value = json.dumps({"skills": {}}) # Mock json lock read
    mock_compute.return_value = "hash123"

    with patch("pathlib.Path.write_text"):
        count = update_lock()
        assert count == 1

@patch("pathlib.Path.read_bytes")
def test_hash_file(mock_read_bytes):
    mock_read_bytes.return_value = b"test content"
    hash_val = _hash_file(Path("dummy.txt"))
    assert hash_val is not None
