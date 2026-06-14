"""Security patterns for skill (.md) and MCP (JS/PY) scanning."""

from __future__ import annotations
import re

TRUSTED_DOMAINS = {
    "github.com", "raw.githubusercontent.com", "gist.githubusercontent.com",
    "anthropic.com", "claude.ai", "api.anthropic.com",
    "npmjs.com", "pypi.org", "registry.npmjs.org",
    "mcp.notion.com", "api.notion.com",
    "googleapis.com", "google.com", "accounts.google.com",
    "openai.com", "api.openai.com",
    "stripe.com", "api.stripe.com",
    "twilio.com", "sendgrid.com", "retellai.com", "elevenlabs.io",
    "n8n.io", "make.com", "us1.make.com", "eu1.make.com",
    "gohighlevel.com", "jsdelivr.net", "unpkg.com", "shields.io",
    "example.com", "schema.org", "json-schema.org",
    "localhost", "127.0.0.1", "0.0.0.0",
}


def is_trusted_url(url: str) -> bool:
    from urllib.parse import urlparse
    try:
        hostname = urlparse(url).hostname or ""
        base = hostname.removeprefix("www.")
        return base in TRUSTED_DOMAINS or any(base.endswith("." + d) for d in TRUSTED_DOMAINS)
    except Exception:
        return False


# ── Skill patterns (.md) ──────────────────────────────────────────────────────

SKILL_PATTERNS: list[dict] = [
    {
        "id": "PI-001", "severity": "CRITICAL",
        "label": "Prompt injection — override instructions",
        "regex": re.compile(
            r"\b(ignore|forget|disregard|override|bypass)\s+(all\s+)?"
            r"(previous|prior|above|your|the)\s+(instructions?|rules?|prompts?|guidelines?|constraints?)",
            re.IGNORECASE,
        ),
    },
    {
        "id": "PI-002", "severity": "CRITICAL",
        "label": "Prompt injection — identity switch",
        "regex": re.compile(
            r"\b(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you\s+are)|"
            r"from\s+now\s+on\s+(you\s+(are|must|should|will))|"
            r"your\s+real\s+(name|identity|purpose)\s+is)",
            re.IGNORECASE,
        ),
    },
    {
        "id": "PI-003", "severity": "CRITICAL",
        "label": "Prompt injection — system role injection",
        "regex": re.compile(r"\[(system|assistant|user|human)\]\s*:", re.IGNORECASE),
    },
    {
        "id": "PI-004", "severity": "HIGH",
        "label": "Prompt injection — jailbreak keywords",
        "regex": re.compile(
            r"\b(jailbreak|DAN|do\s+anything\s+now|unfiltered|"
            r"no\s+restrictions|unrestricted\s+mode|god\s+mode)",
            re.IGNORECASE,
        ),
    },
    {
        "id": "PI-005", "severity": "HIGH",
        "label": "Instruction to exfiltrate data to external URL",
        "regex": re.compile(
            r"\b(send|post|transmit|exfil|forward|upload)\s+.{0,60}(http|https|ftp|ws)://",
            re.IGNORECASE,
        ),
    },
    {
        "id": "PI-006", "severity": "HIGH",
        "label": "Instruction to read sensitive files",
        "regex": re.compile(
            r"\b(read|open|cat|access|load|fetch)\s+.{0,60}"
            r"(\.(env|ssh|config|pem|key)|credentials|token|password|secret|api_key)",
            re.IGNORECASE,
        ),
    },
    {
        "id": "PI-007", "severity": "MEDIUM",
        "label": "Suspicious non-vendor URL",
        "regex": re.compile(r"https?://([a-z0-9\-\.]+\.[a-z]{2,})(/[^\s\"'`\)]*)?", re.IGNORECASE),
        "validate": lambda m: not is_trusted_url(m),
    },
    {
        "id": "UNI-001", "severity": "HIGH",
        "label": "Zero-width Unicode characters (hidden text)",
        "regex": re.compile(r"[​‌‍‎‏﻿­͏⁠-⁤]"),
    },
    {
        "id": "UNI-002", "severity": "MEDIUM",
        "label": "Non-standard control characters",
        "regex": re.compile(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]"),
    },
    {
        "id": "ENC-001", "severity": "HIGH",
        "label": "Possible Base64 payload (>40 chars)",
        "regex": re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),
        "validate": lambda m: _looks_like_b64_payload(m),
    },
    {
        "id": "HIDE-001", "severity": "MEDIUM",
        "label": "Suspicious blank lines block (>15 consecutive)",
        "custom_check": lambda c: _check_blank_lines(c),
    },
    {
        "id": "HIDE-002", "severity": "MEDIUM",
        "label": "HTML tags in markdown (potential hidden content)",
        "regex": re.compile(r"<(style|script|iframe|object|embed|form|input|textarea)[^>]*>", re.IGNORECASE),
    },
]


def _looks_like_b64_payload(s: str) -> bool:
    import base64
    try:
        decoded = base64.b64decode(s + "==").decode("utf-8", errors="replace")
        return bool(re.search(r"[a-z]{4,}", decoded, re.IGNORECASE)) and not all(c < " " for c in decoded)
    except Exception:
        return False


def _check_blank_lines(content: str) -> list[str]:
    import re as _re
    matches = _re.findall(r"(\n\s*){16,}", content)
    return [f"{m.count(chr(10))} consecutive blank lines" for m in matches]


# ── MCP patterns (JS/TS/PY) ───────────────────────────────────────────────────

MCP_PATTERNS: list[dict] = [
    {
        "id": "NET-001", "severity": "HIGH",
        "label": "External HTTP call (fetch/axios/requests)",
        "regex": re.compile(
            r"\b(fetch|axios\.get|axios\.post|axios\.|got\.get|got\.post|"
            r"requests\.(get|post|put|patch|delete|request)|urllib\.request|httpx\.)\s*[\(\.]",
        ),
        "skip_comments": True,
    },
    {
        "id": "NET-002", "severity": "HIGH",
        "label": "Native http.request / https.request",
        "regex": re.compile(r"\b(https?\.request|https?\.get)\s*\("),
        "skip_comments": True,
    },
    {
        "id": "NET-003", "severity": "MEDIUM",
        "label": "WebSocket connection",
        "regex": re.compile(r"\bnew\s+WebSocket\s*\(|ws://|wss://"),
        "skip_comments": True,
    },
    {
        "id": "FS-001", "severity": "CRITICAL",
        "label": "Access to credential files (.env, .ssh, tokens)",
        "regex": re.compile(
            r"""['"` ](\.|~/|/Users/|/home/)[^'"` ]*"""
            r"""(\.(env|pem|key|p12|pfx)|\.ssh/|\.config/|credentials|token\.json|api[-_]key)""",
            re.IGNORECASE,
        ),
    },
    {
        "id": "FS-002", "severity": "HIGH",
        "label": "Reading sensitive environment variables",
        "regex": re.compile(
            r"(process\.env\.|os\.(environ|getenv)\s*[\[(]?\s*['\"])[^'\"` \n]*(KEY|SECRET|TOKEN|PASSWORD)[^'\"` \n]*",
            re.IGNORECASE,
        ),
    },
    {
        "id": "EXEC-001", "severity": "CRITICAL",
        "label": "eval() — dynamic code execution",
        "regex": re.compile(r"\beval\s*\("),
        "skip_comments": True,
    },
    {
        "id": "EXEC-002", "severity": "HIGH",
        "label": "new Function() — dynamic code execution",
        "regex": re.compile(r"new\s+Function\s*\("),
        "skip_comments": True,
    },
    {
        "id": "EXEC-003", "severity": "HIGH",
        "label": "exec/spawn/subprocess — system command execution",
        "regex": re.compile(
            r"\b(execSync|spawnSync|spawn|shell\.exec|subprocess\.(run|Popen|call|check_output)|os\.(system|popen))\s*\(",
        ),
        "skip_comments": True,
    },
    {
        "id": "OBF-001", "severity": "HIGH",
        "label": "Buffer.from base64 (possible obfuscated payload)",
        "regex": re.compile(r"Buffer\.from\s*\([^)]+,\s*['\"]base64['\"]\)"),
        "skip_comments": True,
    },
    {
        "id": "CRED-001", "severity": "CRITICAL",
        "label": "Hardcoded credential (long key string)",
        "regex": re.compile(
            r"""['"`](sk-[a-zA-Z0-9]{20,}|AIza[a-zA-Z0-9\-_]{30,}|"""
            r"""ghp_[a-zA-Z0-9]{30,}|xox[bpoas]-[a-zA-Z0-9\-]+|ya29\.[a-zA-Z0-9\-_]+)['"`]""",
        ),
        "skip_comments": True,
    },
    {
        "id": "MCP-001", "severity": "CRITICAL",
        "label": "Prompt injection in MCP tool description",
        "regex": re.compile(
            r"(description|name)\s*:\s*[`'\"]{1,3}[^`'\"]*\b"
            r"(ignore|override|bypass|you\s+are\s+now|from\s+now\s+on)\b[^`'\"]*[`'\"]{1,3}",
            re.IGNORECASE,
        ),
    },
    {
        "id": "MCP-002", "severity": "HIGH",
        "label": "Hardcoded non-localhost URL in MCP",
        "regex": re.compile(
            r"""['\"](https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[a-z0-9\-\.]+\.[a-z]{2,})['\"]""",
            re.IGNORECASE,
        ),
        "validate": lambda m: not is_trusted_url(m.strip("'\"")),
    },
]


# ── ENV patterns ──────────────────────────────────────────────────────────────

ENV_PATTERNS: list[dict] = [
    {
        "id": "ENV-001", "severity": "HIGH",
        "label": "Anthropic/OpenAI/Claude API key in .env",
        "regex": re.compile(r"(ANTHROPIC|OPENAI|CLAUDE)_API_KEY\s*=\s*\S{20,}", re.IGNORECASE),
    },
    {
        "id": "ENV-002", "severity": "MEDIUM",
        "label": "Non-empty token/secret field",
        "regex": re.compile(
            r"^.*?(TOKEN|SECRET|PASSWORD|PASS|KEY|CREDENTIAL)[^=]*\s*=\s*\S{8,}",
            re.IGNORECASE | re.MULTILINE,
        ),
    },
    {
        "id": "ENV-003", "severity": "LOW",
        "label": "Empty .env field (likely placeholder)",
        "regex": re.compile(r"^([A-Z_]+)\s*=$", re.MULTILINE),
    },
]
