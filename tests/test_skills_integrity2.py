import pytest
from pathlib import Path
from sentinel.skills.integrity import _hash_dir, all_skill_dirs, compute_hash, load_lock, save_lock, verify_hash
import json
import tempfile
import os

def test_hash_dir():
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp)
        (p / "f1.txt").write_text("hello")
        (p / "f2.txt").write_text("world")
        h = _hash_dir(p)
        assert h is not None

def test_all_skill_dirs():
    with tempfile.TemporaryDirectory() as tmp:
        import sentinel.skills.integrity
        with pytest.MonkeyPatch.context() as m:
            d1 = Path(tmp) / ".claude" / "skills"
            d1.mkdir(parents=True)
            (d1 / "test.md").write_text("test")
            # Override SKILL_DIRS directly
            m.setattr(sentinel.skills.integrity, "SKILL_DIRS", [d1])
            dirs = list(all_skill_dirs())
            assert len(dirs) > 0

def test_compute_hash():
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "f.txt"
        p.write_text("abc")
        assert compute_hash(p) is not None
        assert compute_hash(Path(tmp)) is not None

def test_load_save_lock():
    with tempfile.TemporaryDirectory() as tmp:
        import sentinel.skills.integrity
        lock_path = Path(tmp) / "sentinel-lock.json"

        with pytest.MonkeyPatch.context() as m:
            m.setattr(sentinel.skills.integrity, "LOCK_FILE", lock_path)
            l = load_lock()
            assert l == {"version": 1, "skills": {}}
            save_lock({"version": 1, "skills": {"a": {"hash": "123"}}})
            l = load_lock()
            assert l["skills"]["a"]["hash"] == "123"

def test_verify_hash():
    with tempfile.TemporaryDirectory() as tmp:
        import sentinel.skills.integrity
        lock_path = Path(tmp) / "sentinel-lock.json"

        p = Path(tmp) / "skill.md"
        p.write_text("content")
        expected_hash = compute_hash(p)

        with pytest.MonkeyPatch.context() as m:
            m.setattr(sentinel.skills.integrity, "LOCK_FILE", lock_path)
            res = verify_hash("skill", p)
            assert res["status"] == "not_tracked"
            save_lock({"version": 1, "skills": {"skill": {"hash": expected_hash}}})
            res = verify_hash("skill", p)
            assert res["status"] == "match"
            p.write_text("new content")
            res = verify_hash("skill", p)
            assert res["status"] == "mismatch"
