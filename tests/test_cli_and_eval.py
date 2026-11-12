import json
from pathlib import Path

import pytest

from triage_bot import cli
from triage_bot.evaluate import Label, load_labels, score
from triage_bot.models import TriageResult
from triage_bot.pipeline import Run
from triage_bot.report import to_markdown

from .conftest import DATA, ROOT, make_finding, make_triage

LABELS = ROOT / "benchmark" / "labels.json"


def test_every_benchmark_finding_has_exactly_one_label():
    from triage_bot.evaluate import match_label
    from triage_bot.sarif import load_findings

    labels = load_labels(LABELS)
    findings = load_findings([DATA / "bandit.sarif"], repo=ROOT)
    matched = []
    for f in findings:
        result = TriageResult(finding=f, triage=make_triage(), source="offline")
        label = match_label(result, labels, ROOT)
        assert label is not None, f"no label for {f.path}:{f.start_line} {f.rules}"
        matched.append(label)
    assert len(set(matched)) == len(labels)


def test_score_counts_dangerous_dismissals():
    labels = [Label("benchmark/app/db.py", "B608", "WHERE name", "true_positive")]
    finding = make_finding(path="benchmark/app/db.py", start_line=7)
    dismissed = TriageResult(
        finding=finding, triage=make_triage(verdict="false_positive"), source="claude"
    )
    s = score([dismissed], labels, ROOT)
    assert (s.total, s.decided, s.correct, s.dangerous_dismissals) == (1, 1, 0, 1)
    assert s.recall == 0.0 and s.precision == 0.0


def test_score_with_nothing_decided_is_zero_not_an_error():
    labels = load_labels(LABELS)
    unlabelled = TriageResult(
        finding=make_finding(path="other.py"), triage=make_triage(), source="claude"
    )
    s = score([unlabelled], labels, ROOT)
    assert (s.total, s.unlabelled, s.coverage, s.accuracy) == (0, 1, 0.0, 0.0)
    assert "no label" in s.to_markdown()


def test_markdown_report_escapes_pipes_and_lists_fixes():
    result = TriageResult(
        finding=make_finding(),
        triage=make_triage(reasoning="a | b"),
        source="guardrail",
        notes=["note | here"],
    )
    md = to_markdown(Run(results=[result], skipped=[make_finding()]))
    assert "a \\| b" in md and "note \\| here" in md
    assert "## Suggested fixes" in md and "parameterised" in md
    assert "1 lower-severity findings were not triaged" in md


def test_cli_eval_offline_on_the_benchmark(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    out = tmp_path / "reports"
    code = cli.main(
        [
            "eval",
            str(DATA / "bandit.sarif"),
            "--repo",
            str(ROOT),
            "--labels",
            str(LABELS),
            "--out",
            str(out),
            "--offline",
        ]
    )
    assert code == 0
    score_md = (out / "score.md").read_text()
    # The offline baseline only dismisses safe patterns, so it never dismisses a real issue.
    assert "| Dangerous dismissals (real issue called a false alarm) | 0 |" in score_md
    assert "| Accuracy on decided findings | 100% |" in score_md
    data = json.loads((out / "triage.json").read_text())
    assert len(data["results"]) == 19
    assert summary.read_text().startswith("# Security triage")


def test_cli_run_fail_on_confirmed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)

    class AlwaysReal:
        source = "claude"

        def triage(self, finding, excerpt):
            return make_triage(evidence_lines=[finding.start_line])

    monkeypatch.setattr(cli, "_triager", lambda args: AlwaysReal())
    base = ["run", str(DATA / "bandit.sarif"), "--repo", str(ROOT), "--out", str(tmp_path)]
    assert cli.main(base) == 0
    assert cli.main([*base, "--fail-on-confirmed", "error"]) == 1


def test_cli_run_with_no_confirmed_issues_passes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    args = [
        "run",
        str(DATA / "bandit.sarif"),
        "--repo",
        str(ROOT),
        "--out",
        str(tmp_path),
        "--offline",
        "--fail-on-confirmed",
        "note",
    ]
    assert cli.main(args) == 0


def test_cli_reports_bad_sarif(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    bad = tmp_path / "bad.sarif"
    bad.write_text("{}")
    assert cli.main(["run", str(bad), "--offline", "--out", str(tmp_path)]) == 2
    assert "not SARIF" in capsys.readouterr().err


def test_cli_builds_a_claude_triager_by_default(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-used")
    args = cli.build_parser().parse_args(["run", "x.sarif", "--effort", "high"])
    triager = cli._triager(args)
    assert triager.source == "claude"
    assert triager.effort == "high"
