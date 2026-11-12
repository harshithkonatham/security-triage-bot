"""Checks applied to every verdict before anyone sees it.

The model is useful but not trusted. A verdict is downgraded to needs_review when its
evidence doesn't check out, and an error-level finding is never dismissed on a guess.
Downgrading is always safe: the worst case is that a human looks at it.
"""

from .context import Excerpt
from .models import Finding, Triage


def apply_guardrails(
    finding: Finding, triage: Triage, excerpt: Excerpt
) -> tuple[Triage, list[str]]:
    if triage.verdict == "needs_review":
        return triage, []

    notes = []
    if not triage.evidence_lines:
        notes.append("No evidence lines were cited.")
    elif outside := [n for n in triage.evidence_lines if not excerpt.covers(n)]:
        notes.append(f"Cited line(s) {outside} are not in the excerpt shown to the model.")
    if (
        triage.verdict == "false_positive"
        and finding.level == "error"
        and triage.confidence != "high"
    ):
        notes.append("An error-level finding can only be dismissed with high confidence.")

    if notes:
        return triage.model_copy(update={"verdict": "needs_review", "suggested_fix": ""}), notes
    return triage, []
