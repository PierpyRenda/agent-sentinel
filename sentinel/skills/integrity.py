"""Hash-based integrity checking for installed skills."""

from __future__ import annotations
import hashlib
import json
from pathlib import Path

LOCK_FILE = Path.home() / ".agent-sentinel" / "skills-lock.json"
SKILL_DIRS = [
    Path.home() / ".claude" / "skills",
    Path.home() / ".kiro" / "skills",
    Path.home() / ".agents" / "skills",
]


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _hash_dir(path: Path) -> str:
    h = hashlib.sha256()
    for f in sorted(f for f in path.rglob("*") if f.is_file()):
        h.update(str(f.relative_to(path)).encode())
        h.update(f.read_bytes())
    return h.hexdigest()


def compute_hash(path: Path) -> str:
    return _hash_dir(path) if path.is_dir() else _hash_file(path)


def load_lock() -> dict:
    if LOCK_FILE.exists():
        return json.loads(LOCK_FILE.read_text())
    return {"version": 1, "skills": {}}


def save_lock(lock: dict) -> None:
    from datetime import datetime, timezone
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    lock["updated_at"] = datetime.now(timezone.utc).isoformat()
    LOCK_FILE.write_text(json.dumps(lock, indent=2))


def verify_hash(name: str, path: Path) -> dict:
    lock = load_lock()
    entry = lock["skills"].get(name)
    current = compute_hash(path)
    if not entry:
        return {"status": "not_tracked", "hash": current}
    if current == entry["hash"]:
        return {"status": "match", "hash": current, "source": entry.get("source", "local")}
    return {"status": "mismatch", "hash": current, "expected": entry["hash"], "source": entry.get("source")}


def all_skill_dirs() -> list[tuple[Path, Path]]:
    """Returns (skills_dir, skill_path) for all installed skills."""
    result = []
    for d in SKILL_DIRS:
        if not d.exists():
            continue
        for entry in sorted(d.iterdir()):
            result.append((d, entry))
    return result


def verify_all() -> list[dict]:
    lock = load_lock()
    results = []
    for skills_dir, skill_path in all_skill_dirs():
        name = skill_path.name.removesuffix(".md")
        current = compute_hash(skill_path)
        entry = lock["skills"].get(name)
        results.append({
            "name": name,
            "dir": str(skills_dir),
            "status": "not_tracked" if not entry else ("match" if current == entry["hash"] else "mismatch"),
            "source": entry.get("source") if entry else None,
        })
    return results


def update_lock() -> int:
    lock = load_lock()
    updated = 0
    for _, skill_path in all_skill_dirs():
        name = skill_path.name.removesuffix(".md")
        current = compute_hash(skill_path)
        if name not in lock["skills"] or lock["skills"][name]["hash"] != current:
            lock["skills"][name] = {"hash": current, "source": "local"}
            updated += 1
    save_lock(lock)
    return updated
