import pytest
from sentinel.keys.vault import SecureBytes, redact

def test_secure_bytes():
    sb = SecureBytes(b"hello world")
    assert sb.to_str() == "hello world"
    assert "SecureBytes" in repr(sb)

def test_secure_bytes_context_manager():
    with SecureBytes("test_key") as sb:
        assert sb.to_str() == "test_key"
        assert len(sb) == 8
    # After exit, it should be wiped
    assert len(sb._buf) == 0

def test_secure_bytes_wipe():
    sb = SecureBytes("secret")
    assert len(sb) == 6
    sb.wipe()
    assert len(sb) == 0

def test_secure_bytes_sha256():
    sb = SecureBytes("test")
    # sha256 of "test"
    assert sb.sha256() == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

def test_redact():
    text = "Here is my key sk-123456789012345 don't steal it"
    # Wait, redact replaces [:6] with **** and [-4:] with the end.
    # original = sk-123456789012345 (length 18)
    # [:6] = sk-123
    # [-4:] = 2345
    # So expected is sk-123****2345
    assert redact(text) == "Here is my key sk-123****2345 don't steal it"
