"""Run triage over a list of findings, most severe first."""

from dataclasses import dataclass, field
from pathlib import Path

from .context import UnsafePathError, build_excerpt
from .guardrails import apply_guardrails
from .models import Finding, Triage, TriageResult
from .triagers import Triager, TriageRefused


@dataclass
class Run:
    results: list[TriageResult] = field(default_factory=list)
    skipped: list[Finding] = field(default_factory=list)  # over --max-findings


def _needs_review(finding: Finding, reason: str) -> TriageResult:
    triage = Triage(
        verdict="needs_review",
        confidence="low",
        reasoning=reason,
        evidence_lines=[],
        suggested_fix="",
    )
    return TriageResult(finding=finding, triage=triage, source="guardrail", notes=[reason])


def triage_all(
    findings: list[Finding], repo: Path, triager: Triager, max_findings: int = 50
) -> Run:
    """Cap the number of findings sent to the model, so a noisy scan can't run up a bill."""
    run = Run(skipped=findings[max_findings:])
    for finding in findings[:max_findings]:
        try:
            excerpt = build_excerpt(repo, finding)
        except UnsafePathError as exc:
            run.results.append(_needs_review(finding, f"Not read: {exc}."))
            continue
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            run.results.append(_needs_review(finding, f"Could not read the code: {exc}."))
            continue

        if excerpt.injection:
            reason = (
                f'Possible prompt injection in the code ("{excerpt.injection}"); '
                "not sent to the model."
            )
            run.results.append(_needs_review(finding, reason))
            continue

        try:
            triage = triager.triage(finding, excerpt)
        except TriageRefused as exc:
            run.results.append(_needs_review(finding, f"The model declined to triage this: {exc}."))
            continue

        triage, notes = apply_guardrails(finding, triage, excerpt)
        if excerpt.redactions:
            notes.append(f"{excerpt.redactions} secret(s) were redacted before triage.")
        source = "guardrail" if triage.verdict == "needs_review" and notes else triager.source
        run.results.append(TriageResult(finding=finding, triage=triage, source=source, notes=notes))
    return run
