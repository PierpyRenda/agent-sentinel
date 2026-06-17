import pytest
from sentinel.keys.validator import validate, Provider, KeyInfo

def test_validate_empty():
    with pytest.raises(ValueError):
        validate("")

def test_validate_too_long():
    with pytest.raises(ValueError):
        validate("a" * 600)

def test_validate_too_short():
    with pytest.raises(ValueError):
        validate("short")

def test_validate_unsafe_chars():
    with pytest.raises(ValueError):
        validate("sk-ant-123\nnewline")

def test_validate_anthropic():
    info = validate("sk-ant-12345678901234567890")
    assert info.provider == Provider.ANTHROPIC
    assert info.valid_format is True
    assert info.hint == "Anthropic API key"

def test_validate_openai():
    info = validate("sk-123456789012345678901234")
    assert info.provider == Provider.OPENAI
    assert info.valid_format is True

def test_validate_unknown():
    info = validate("unknown-prefix-1234567890")
    assert info.provider == Provider.UNKNOWN
    assert info.valid_format is False
