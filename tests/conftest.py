from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from triage_bot.models import Finding, Triage

ROOT = Path(__file__).resolve().parent.parent
DATA = Path(__file__).resolve().parent / "data"


def make_finding(**overrides: Any) -> Finding:
    values: dict[str, Any] = {
        "id": "abc",
        "tools": ["Bandit"],
        "rules": ["B608"],
        "level": "warning",
        "message": "Possible SQL injection",
        "path": "benchmark/app/db.py",
        "start_line": 7,
        "end_line": 7,
        "cwes": ["CWE-89"],
    }
    values.update(overrides)
    return Finding(**values)


def make_triage(**overrides: Any) -> Triage:
    values: dict[str, Any] = {
        "verdict": "true_positive",
        "confidence": "high",
        "reasoning": "User input is formatted into SQL.",
        "evidence_lines": [7],
        "suggested_fix": "Use a parameterised query.",
    }
    values.update(overrides)
    return Triage(**values)


class FakeClient:
    """Stands in for anthropic.Anthropic: returns queued verdicts and records each request."""

    def __init__(self, *responses: Triage | str) -> None:
        self.responses = list(responses)
        self.requests: list[dict[str, Any]] = []
        self.beta = SimpleNamespace(messages=SimpleNamespace(parse=self._parse))

    def _parse(self, **kwargs: Any) -> SimpleNamespace:
        self.requests.append(kwargs)
        item = self.responses.pop(0)
        if item == "refusal":
            return SimpleNamespace(
                stop_reason="refusal", stop_details="category=cyber", parsed_output=None
            )
        if item == "truncated":
            return SimpleNamespace(stop_reason="max_tokens", parsed_output=None)
        return SimpleNamespace(stop_reason="end_turn", parsed_output=item)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A tiny repository with code the tests can point findings at."""
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "db.py").write_text(
        "import sqlite3\n\n\ndef find(conn, name):\n"
        "    return conn.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n"
    )
    return tmp_path
