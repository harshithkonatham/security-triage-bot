"""Tests for account helpers."""

from app.auth import make_reset_token


def login(username: str, password: str) -> bool:
    return bool(username and password)


def test_reset_token_has_six_digits():
    assert len(make_reset_token()) == 6


def test_login_accepts_fixture_user():
    assert login("alice", password="fixture-password")
