import pytest
from sentinel.skills.patterns import is_trusted_url, _looks_like_b64_payload, _check_blank_lines

def test_is_trusted_url():
    assert is_trusted_url("https://github.com/foo") is True
    assert is_trusted_url("https://api.openai.com/v1") is True
    assert is_trusted_url("https://malicious.com") is False
    assert is_trusted_url("not a url") is False

def test_looks_like_b64_payload():
    import base64
    valid_b64 = base64.b64encode(b"this is a test payload").decode()
    assert _looks_like_b64_payload(valid_b64) is True
    assert _looks_like_b64_payload("not_base64_data_obviously!!!") is False

def test_check_blank_lines():
    normal = "Hello\nWorld"
    assert len(_check_blank_lines(normal)) == 0
    many_blanks = "Hello" + "\n" * 20 + "World"
    assert len(_check_blank_lines(many_blanks)) == 1
