"""Command line: `triage run` for real scans, `triage eval` for the benchmark."""

import argparse
import sys
from pathlib import Path

from .evaluate import load_labels, score
from .models import LEVEL_RANK
from .pipeline import Run, triage_all
from .report import to_markdown, write_reports
from .sarif import SarifError, load_findings
from .triagers import ClaudeTriager, OfflineTriager, Triager


def _triager(args: argparse.Namespace) -> Triager:
    if args.offline:
        return OfflineTriager()
    return ClaudeTriager(model=args.model, effort=args.effort)


def _run(args: argparse.Namespace) -> Run:
    findings = load_findings(args.sarif, repo=args.repo)
    return triage_all(findings, args.repo, _triager(args), max_findings=args.max_findings)


def cmd_run(args: argparse.Namespace) -> int:
    run = _run(args)
    md, _ = write_reports(run, args.out)
    print(md.read_text(encoding="utf-8"))
    if args.fail_on_confirmed:
        threshold = LEVEL_RANK[args.fail_on_confirmed]
        confirmed = [
            r
            for r in run.results
            if r.triage.verdict == "true_positive" and r.finding.rank >= threshold
        ]
        if confirmed:
            print(f"{len(confirmed)} confirmed issue(s) at '{args.fail_on_confirmed}' or above.")
            return 1
    return 0


def cmd_eval(args: argparse.Namespace) -> int:
    run = _run(args)
    result = score(run.results, load_labels(args.labels), args.repo)
    write_reports(run, args.out)
    text = (
        f"## Benchmark score ({'offline' if args.offline else args.model})\n\n"
        + result.to_markdown()
    )
    (args.out / "score.md").write_text(text, encoding="utf-8")
    print(to_markdown(run))
    print(text)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="triage", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name, fn, help_text in (
        ("run", cmd_run, "Triage SARIF findings and write a report."),
        ("eval", cmd_eval, "Triage, then score the verdicts against labels."),
    ):
        p = sub.add_parser(name, help=help_text)
        p.set_defaults(func=fn)
        p.add_argument("sarif", nargs="+", type=Path, help="SARIF file(s) from any scanner.")
        p.add_argument("--repo", type=Path, default=Path("."), help="Repository the scan ran on.")
        p.add_argument("--out", type=Path, default=Path("reports"))
        p.add_argument("--offline", action="store_true", help="Rule-based baseline, no API key.")
        p.add_argument("--model", default="claude-opus-5-5")
        p.add_argument("--effort", default="medium", choices=["low", "medium", "high", "xhigh"])
        p.add_argument("--max-findings", type=int, default=50)
        if name == "run":
            p.add_argument(
                "--fail-on-confirmed",
                choices=["note", "warning", "error"],
                help="Exit 1 if a confirmed real issue is at this level or above.",
            )
        else:
            p.add_argument("--labels", type=Path, default=Path("benchmark/labels.json"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        code: int = args.func(args)
    except SarifError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return code


if __name__ == "__main__":
    raise SystemExit(main())
