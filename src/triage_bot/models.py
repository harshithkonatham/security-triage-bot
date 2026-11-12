"""Data shapes shared by the parser, the triagers and the reports."""

from typing import Literal

from pydantic import BaseModel, Field

Verdict = Literal["true_positive", "false_positive", "needs_review"]
Confidence = Literal["low", "medium", "high"]
Source = Literal["claude", "offline", "guardrail"]

LEVEL_RANK = {"error": 3, "warning": 2, "note": 1, "none": 0}


class Finding(BaseModel):
    """One scanner result after deduplication across tools."""

    id: str
    tools: list[str]
    rules: list[str]
    level: str
    message: str
    path: str
    start_line: int
    end_line: int
    cwes: list[str] = []

    @property
    def rank(self) -> int:
        return LEVEL_RANK.get(self.level, 0)


class Triage(BaseModel):
    """The verdict Claude returns for one finding (also the structured-output schema)."""

    verdict: Verdict
    confidence: Confidence
    reasoning: str = Field(description="2-4 sentences explaining the verdict.")
    evidence_lines: list[int] = Field(
        description="Line numbers from the excerpt that support the verdict."
    )
    suggested_fix: str = Field(
        description="For true_positive, a minimal code change. Otherwise an empty string."
    )


class TriageResult(BaseModel):
    finding: Finding
    triage: Triage
    source: Source
    notes: list[str] = []
