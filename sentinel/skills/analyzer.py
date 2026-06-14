"""Skill (.md) and MCP (JS/PY) file analyzers."""

from __future__ import annotations
import re
from pathlib import Path
from typing import NamedTuple

from sentinel.skills.patterns import SKILL_PATTERNS, MCP_PATTERNS, ENV_PATTERNS


class Finding(NamedTuple):
    id: str
    severity: str
    label: str
    file: str | None
    matches: list[str]


SKIP_DIRS = {"node_modules", ".git", "dist", "build", "__pycache__", ".venv", "venv"}
CODE_EXTS = {".js", ".ts", ".mjs", ".py"}


def _get_files(path: Path, exts: set[str] | None = None) -> list[Path]:
    results = []
    if not path.exists():
        return results
    if path.is_file():
        return [path] if (exts is None or path.suffix in exts) else []
    for entry in path.rglob("*"):
        if any(p in SKIP_DIRS for p in entry.parts):
            continue
        if entry.is_file() and (exts is None or entry.suffix in exts):
            results.append(entry)
    return sorted(results)


def _strip_comments(content: str, ext: str) -> str:
    if ext in (".js", ".ts", ".mjs"):
        content = re.sub(r"//[^\n]*", "", content)
        content = re.sub(r"/\*.*?\*/", "", content, flags=re.DOTALL)
    elif ext == ".py":
        content = re.sub(r"#[^\n]*", "", content)
        content = re.sub(r"'''.*?'''", "", content, flags=re.DOTALL)
        content = re.sub(r'""".*?"""', "", content, flags=re.DOTALL)
    return content


def analyze_skill(path: Path) -> list[Finding]:
    content = path.read_text(encoding="utf-8", errors="replace")
    findings: list[Finding] = []

    for pat in SKILL_PATTERNS:
        if "custom_check" in pat:
            results = pat["custom_check"](content)
            if results:
                findings.append(Finding(pat["id"], pat["severity"], pat["label"], None, results))
            continue

        raw_matches = pat["regex"].findall(content)
        if not raw_matches:
            continue

        flat = [m if isinstance(m, str) else " ".join(m) for m in raw_matches]

        if "validate" in pat:
            # For full_match patterns we need finditer
            full_matches = [m.group(0) for m in pat["regex"].finditer(content)]
            flat = [m for m in full_matches if pat["validate"](m)]

        if not flat:
            continue

        unique = list(dict.fromkeys(s.strip()[:80] for s in flat))
        findings.append(Finding(pat["id"], pat["severity"], pat["label"], None, unique))

    return findings


def analyze_mcp(target: Path) -> list[Finding]:
    files = _get_files(target, CODE_EXTS)
    findings: list[Finding] = []

    for file in files:
        raw = file.read_text(encoding="utf-8", errors="replace")
        stripped = _strip_comments(raw, file.suffix)
        rel = str(file.relative_to(target)) if target.is_dir() else str(file)

        for pat in MCP_PATTERNS:
            content = stripped if pat.get("skip_comments") else raw
            full_matches = [m.group(0) for m in pat["regex"].finditer(content)]
            if not full_matches:
                continue

            if "validate" in pat:
                full_matches = [m for m in full_matches if pat["validate"](m)]
            if not full_matches:
                continue

            unique = list(dict.fromkeys(s.strip()[:100] for s in full_matches))
            findings.append(Finding(pat["id"], pat["severity"], pat["label"], rel, unique))

    return findings


def analyze_env(path: Path) -> list[Finding]:
    content = path.read_text(encoding="utf-8", errors="replace")
    findings: list[Finding] = []

    for pat in ENV_PATTERNS:
        raw_matches = [m.group(0) for m in pat["regex"].finditer(content)]
        if not raw_matches:
            continue
        # Redact values
        redacted = list(dict.fromkeys(
            re.sub(r"=\S{4,}", "=***", m).strip()[:80] for m in raw_matches
        ))
        findings.append(Finding(pat["id"], pat["severity"], pat["label"], None, redacted))

    return findings
