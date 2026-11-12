"""Markdown and JSON reports, plus the GitHub Actions job summary."""

import json
import os
from collections import Counter
from pathlib import Path

from .pipeline import Run

ICONS = {
    "true_positive": "🔴 real issue",
    "false_positive": "⚪ false alarm",
    "needs_review": "🟡 needs review",
}


def to_markdown(run: Run, title: str = "Security triage") -> str:
    counts = Counter(r.triage.verdict for r in run.results)
    lines = [
        f"# {title}",
        "",
        f"**{len(run.results)} findings triaged:** "
        f"{counts['true_positive']} real issues, {counts['false_positive']} false alarms, "
        f"{counts['needs_review']} need a human.",
    ]
    if run.skipped:
        lines.append(
            f"\n{len(run.skipped)} lower-severity findings were not triaged (over the limit)."
        )
    lines += [
        "",
        "| Verdict | Level | Rule | Location | Why |",
        "|---|---|---|---|---|",
    ]
    for r in run.results:
        f, t = r.finding, r.triage
        why = t.reasoning.replace("|", "\\|").replace("\n", " ")
        if r.notes:
            why += " _(" + " ".join(r.notes).replace("|", "\\|") + ")_"
        lines.append(
            f"| {ICONS[t.verdict]} ({t.confidence}) | {f.level} | {', '.join(f.rules)} "
            f"| `{f.path}:{f.start_line}` | {why} |"
        )

    fixes = [r for r in run.results if r.triage.suggested_fix]
    if fixes:
        lines += ["", "## Suggested fixes", ""]
        for r in fixes:
            lines += [
                f"<details><summary><code>{r.finding.path}:{r.finding.start_line}</code> "
                f"({', '.join(r.finding.rules)})</summary>",
                "",
                "```",
                r.triage.suggested_fix.strip(),
                "```",
                "</details>",
                "",
            ]
    return "\n".join(lines) + "\n"


def write_reports(run: Run, out: Path) -> tuple[Path, Path]:
    out.mkdir(parents=True, exist_ok=True)
    md, js = out / "triage.md", out / "triage.json"
    markdown = to_markdown(run)
    md.write_text(markdown, encoding="utf-8")
    payload = {
        "results": [r.model_dump() for r in run.results],
        "skipped": [f.model_dump() for f in run.skipped],
    }
    js.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(markdown)
    return md, js
