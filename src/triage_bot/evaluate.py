"""Score triage verdicts against hand-written labels.

The metric that matters most is dangerous dismissals: real issues the bot called false
alarms. A bot that dismisses real vulnerabilities is worse than no bot at all.
"""

import json
from dataclasses import dataclass
from pathlib import Path

from .context import resolve_in_repo
from .models import TriageResult


@dataclass(frozen=True)
class Label:
    path: str
    rule: str
    contains: str
    label: str


@dataclass(frozen=True)
class Score:
    total: int
    unlabelled: int
    decided: int
    correct: int
    flagged_real: int  # verdict true_positive
    flagged_real_correct: int
    actual_real: int
    dangerous_dismissals: int  # actual true_positive called false_positive

    @property
    def coverage(self) -> float:
        return self.decided / self.total if self.total else 0.0

    @property
    def accuracy(self) -> float:
        return self.correct / self.decided if self.decided else 0.0

    @property
    def precision(self) -> float:
        return self.flagged_real_correct / self.flagged_real if self.flagged_real else 0.0

    @property
    def recall(self) -> float:
        return self.flagged_real_correct / self.actual_real if self.actual_real else 0.0

    def to_markdown(self) -> str:
        rows = [
            ("Findings scored", f"{self.total}"),
            ("Decided (not sent to a human)", f"{self.decided} ({self.coverage:.0%})"),
            ("Accuracy on decided findings", _pct(self.correct, self.decided)),
            ("Precision on real issues", _pct(self.flagged_real_correct, self.flagged_real)),
            ("Recall on real issues", _pct(self.flagged_real_correct, self.actual_real)),
            (
                "Dangerous dismissals (real issue called a false alarm)",
                f"{self.dangerous_dismissals}",
            ),
        ]
        if self.unlabelled:
            rows.append(("Findings with no label (not scored)", f"{self.unlabelled}"))
        return (
            "\n".join(["| Metric | Value |", "|---|---|", *(f"| {k} | {v} |" for k, v in rows)])
            + "\n"
        )


def _pct(part: int, whole: int) -> str:
    return f"{part / whole:.0%}" if whole else "n/a"


def load_labels(path: Path) -> list[Label]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [
        Label(item["path"], item["rule"], item["contains"], item["label"])
        for item in data["labels"]
    ]


def match_label(result: TriageResult, labels: list[Label], repo: Path) -> Label | None:
    f = result.finding
    try:
        lines = resolve_in_repo(repo, f.path).read_text(encoding="utf-8").splitlines()
        flagged = lines[f.start_line - 1]
    except (OSError, IndexError, ValueError):
        return None
    for label in labels:
        if label.path == f.path and label.rule in f.rules and label.contains in flagged:
            return label
    return None


def score(results: list[TriageResult], labels: list[Label], repo: Path) -> Score:
    total = unlabelled = decided = correct = 0
    flagged_real = flagged_real_correct = actual_real = dangerous = 0
    for result in results:
        label = match_label(result, labels, repo)
        if label is None:
            unlabelled += 1
            continue
        total += 1
        verdict = result.triage.verdict
        actual_real += label.label == "true_positive"
        if verdict == "needs_review":
            continue
        decided += 1
        correct += verdict == label.label
        if verdict == "true_positive":
            flagged_real += 1
            flagged_real_correct += label.label == "true_positive"
        if verdict == "false_positive" and label.label == "true_positive":
            dangerous += 1
    return Score(
        total,
        unlabelled,
        decided,
        correct,
        flagged_real,
        flagged_real_correct,
        actual_real,
        dangerous,
    )
