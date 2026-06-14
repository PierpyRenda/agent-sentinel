# agent-sentinel

Security toolkit for Claude Code agents, MCP servers and skills.

## Install

```bash
pip install agent-sentinel
```

## Usage

```bash
# Scan a skill for prompt injection
sentinel skill scan ~/.claude/skills/my-skill/

# Verify all installed skills haven't been tampered
sentinel skill verify-all

# Check MCP configs for suspicious entries
sentinel skill scan-configs

# Scan .env files for exposed secrets
sentinel skill scan-env

# Check if an API key is compromised
sentinel keys scan --key sk-ant-...
```
