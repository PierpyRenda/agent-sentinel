"""Scan active MCP config files for suspicious entries."""

from __future__ import annotations
import json
from pathlib import Path

from sentinel.skills.patterns import is_trusted_url

MCP_CONFIGS = [
    Path.home() / ".mcp.json",
    Path.home() / "Orchestrator" / ".mcp.json",
    Path.home() / ".mcp-core.json",
    Path.home() / ".mcp-full.json",
]

ALLOWED_COMMANDS = {"node", "npx", "python", "python3", "uvx", "deno", "bun", "uv"}


def scan_configs() -> list[dict]:
    results = []
    for config_path in MCP_CONFIGS:
        if not config_path.exists():
            results.append({"path": str(config_path), "status": "not_found", "servers": []})
            continue

        try:
            config = json.loads(config_path.read_text())
        except json.JSONDecodeError as e:
            results.append({"path": str(config_path), "status": "invalid_json", "error": str(e), "servers": []})
            continue

        servers = []
        for name, entry in (config.get("mcpServers") or {}).items():
            issues = []

            if entry.get("type") == "url" and entry.get("url"):
                if not is_trusted_url(entry["url"]):
                    issues.append(f"Non-vendor URL: {entry['url']}")

            if entry.get("command"):
                base = Path(entry["command"]).name
                if base not in ALLOWED_COMMANDS and not entry["command"].endswith(".sh"):
                    issues.append(f"Unusual command: {entry['command']}")

            for k, v in (entry.get("env") or {}).items():
                if (
                    isinstance(v, str)
                    and len(v) > 20
                    and not v.startswith("${")
                    and not v.startswith("$")
                    and not (v.startswith("/") or v.startswith("~"))
                ):
                    if any(kw in k.lower() for kw in ("key", "token", "secret", "password", "credential")):
                        issues.append(f"Hardcoded secret in env.{k}")

            servers.append({"name": name, "issues": issues})

        results.append({"path": str(config_path), "status": "ok", "servers": servers})

    return results


def scan_env_files() -> list[dict]:
    from sentinel.skills.analyzer import analyze_env

    env_dirs = [
        Path.home() / "Orchestrator",
        Path.home() / "Orchestrator" / "stable-gateway",
    ]

    results = []
    for d in env_dirs:
        if not d.exists():
            continue
        for f in d.iterdir():
            if f.name == ".env" or f.name.startswith(".env."):
                findings = analyze_env(f)
                results.append({
                    "path": str(f),
                    "findings": [
                        {"id": fi.id, "severity": fi.severity, "label": fi.label, "matches": fi.matches}
                        for fi in findings
                    ],
                })

    gitignore = Path.home() / "Orchestrator" / ".gitignore"
    gitignore_ok = gitignore.exists() and ".env" in gitignore.read_text()
    results.append({"gitignore_check": gitignore_ok})

    return results
