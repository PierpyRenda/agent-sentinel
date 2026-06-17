import pytest
from unittest.mock import patch
from sentinel.keys.scanners.gitguardian import scan
from sentinel.keys.vault import SecureBytes

@patch("os.getenv", return_value="token")
@patch("httpx.Client.post")
def test_scan_gitguardian_found(mock_post, mock_getenv):
    class MockResponse:
        status_code = 200
        def json(self):
            return {
                "policy_breaks": [
                    {"known_secret": True, "validity": "valid", "type": "Test Key"}
                ]
            }
        def raise_for_status(self):
            pass

    mock_post.return_value = MockResponse()

    sb = SecureBytes("test_key")
    result = scan(sb)
    assert result["found"] is True
    assert "known incident" in result["summary"]

@patch("os.getenv", return_value="token")
@patch("httpx.Client.post")
def test_scan_gitguardian_not_found(mock_post, mock_getenv):
    class MockResponse:
        status_code = 200
        def json(self):
            return {
                "policy_breaks": [
                    {"known_secret": False, "validity": "valid", "type": "Test Key"}
                ]
            }
        def raise_for_status(self):
            pass

    mock_post.return_value = MockResponse()

    sb = SecureBytes("test_key")
    result = scan(sb)
    assert result["found"] is False

@patch("os.getenv", return_value=None)
def test_scan_gitguardian_no_token(mock_getenv):
    sb = SecureBytes("test_key")
    result = scan(sb)
    assert result["found"] is False
    assert "Skipped" in result["summary"]
