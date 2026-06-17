import pytest
from sentinel.skills.analyzer import _strip_comments

def test_strip_comments_js():
    js = "var x = 1; // comment\n/* block */ var y = 2;"
    res = _strip_comments(js, ".js")
    assert "comment" not in res
    assert "block" not in res

def test_strip_comments_py():
    py = "x = 1 # comment\n'''block''' y = 2"
    res = _strip_comments(py, ".py")
    assert "comment" not in res
    assert "block" not in res
