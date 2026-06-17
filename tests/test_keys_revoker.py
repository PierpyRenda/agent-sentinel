import pytest
from unittest.mock import patch
from sentinel.keys.revoker import revoke, _manual_steps, Provider
from sentinel.keys.vault import SecureBytes

def test_revoke_unsupported_provider():
    sb = SecureBytes(b"sk-ant-123")
    result = revoke(sb, Provider.ANTHROPIC)
    assert result["revoked"] is False
    assert "Auto-revocation not supported" in result["message"]
    assert "manual_steps" in result

@patch("shutil.which")
@patch("subprocess.run")
def test_revoke_stripe_success(mock_run, mock_which):
    mock_which.return_value = "/usr/bin/stripe"
    class MockResult:
        returncode = 0
    mock_run.return_value = MockResult()

    sb = SecureBytes(b"rk_live_123")
    result = revoke(sb, Provider.STRIPE_LIVE)
    assert result["revoked"] is True

@patch("shutil.which")
def test_revoke_stripe_no_cli(mock_which):
    mock_which.return_value = None

    sb = SecureBytes(b"rk_live_123")
    result = revoke(sb, Provider.STRIPE_LIVE)
    assert result["revoked"] is False
    assert "Stripe CLI not installed" in result["message"] or "does not support" in result["message"]

def test_manual_steps():
    steps = _manual_steps(Provider.OPENAI)
    assert len(steps) > 0
    assert "platform.openai.com/api-keys" in steps[0]
