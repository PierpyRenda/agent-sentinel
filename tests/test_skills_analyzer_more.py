import pytest
from pathlib import Path
from sentinel.skills.analyzer import analyze_env

def test_analyze_env():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / ".env"
        p.write_text("OPENAI_API_KEY=sk-12345678901234567890\nSECRET_KEY=longsecretpassword")
        findings = analyze_env(p)
        assert len(findings) > 0
