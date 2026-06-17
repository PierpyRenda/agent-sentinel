import pytest
from unittest.mock import patch
from sentinel.keys.scanners.github import scan, _parse_reset_wait, _rate_limited
from sentinel.keys.vault import SecureBytes

@patch("httpx.Client.get")
def test_scan_github_found(mock_get):
    class MockResponse:
        status_code = 200
        def json(self):
            return {
                "total_count": 1,
                "items": [{"repository": {"full_name": "test/repo"}, "path": "test.txt", "html_url": "url"}]
            }
        def raise_for_status(self):
            pass

    mock_get.return_value = MockResponse()

    sb = SecureBytes("test_key")
    result = scan(sb, github_token="test_token")
    assert result["found"] is True
    assert len(result["hits"]) == 1

@patch("httpx.Client.get")
def test_scan_github_rate_limited(mock_get):
    class MockResponse:
        status_code = 403
        text = "rate limit exceeded"
        headers = {}
        def raise_for_status(self):
            pass

    mock_get.return_value = MockResponse()

    sb = SecureBytes("test_key")
    # Setting max retries to 1 or mocking sleep
    with patch("time.sleep"):
        result = scan(sb, github_token="test_token")
    assert result["found"] is False
    assert "Rate limited" in result["summary"]
