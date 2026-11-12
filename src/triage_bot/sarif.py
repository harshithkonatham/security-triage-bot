"""Read SARIF 2.1.0 files from any scanner and merge duplicate findings.

Semgrep, Bandit, CodeQL, Checkov, Grype and Gitleaks can all write SARIF, so this is the
one input format the bot needs. Two tools often flag the same line for the same weakness;
those become one finding that lists both tools.
"""

import hashlib
import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from .models import LEVEL_RANK, Finding

_CWE = re.compile(r"cwe[-/:]?(\d+)", re.IGNORECASE)


class SarifError(ValueError):
    """The file is not usable SARIF."""


def load_findings(paths: Iterable[Path], repo: Path | None = None) -> list[Finding]:
    """Absolute paths inside `repo` are made relative, so tools that report them still merge."""
    root = repo.resolve() if repo else None
    raw: list[Finding] = []
    for path in paths:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SarifError(f"{path}: {exc}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("runs"), list):
            raise SarifError(f"{path}: no 'runs' array, so this is not SARIF")
        for run in data["runs"]:
            raw.extend(_run_findings(run, root))
    return dedupe(raw)


def _run_findings(run: dict[str, Any], root: Path | None) -> list[Finding]:
    driver = run.get("tool", {}).get("driver", {})
    tool = driver.get("name", "unknown")
    rules = {str(r.get("id")): r for r in driver.get("rules") or [] if isinstance(r, dict)}
    findings = []
    for result in run.get("results") or []:
        finding = _to_finding(tool, rules, result, root)
        if finding is not None:
            findings.append(finding)
    return findings


def _to_finding(
    tool: str, rules: dict[str, dict[str, Any]], result: dict[str, Any], root: Path | None
) -> Finding | None:
    rule_id = result.get("ruleId") or result.get("rule", {}).get("id") or "unknown"
    rule = rules.get(rule_id, {})
    locations = result.get("locations") or []
    if not locations:
        return None  # e.g. a repository-level finding with no file to show
    physical = locations[0].get("physicalLocation", {})
    uri = physical.get("artifactLocation", {}).get("uri")
    if not uri:
        return None
    region = physical.get("region", {})
    start = int(region.get("startLine", 1))
    level = (
        result.get("level")
        or rule.get("defaultConfiguration", {}).get("level")
        or "warning"  # the SARIF default when no level is given
    )
    tags = [
        *rule.get("properties", {}).get("tags", []),
        *result.get("properties", {}).get("tags", []),
    ]
    cwes = sorted({f"CWE-{m.group(1)}" for tag in tags if (m := _CWE.search(str(tag)))})
    return Finding(
        id="",
        tools=[tool],
        rules=[rule_id],
        level=level if level in LEVEL_RANK else "warning",
        message=result.get("message", {}).get("text", "").strip(),
        path=_normalise_uri(uri, root),
        start_line=start,
        end_line=int(region.get("endLine", start)),
        cwes=cwes,
    )


def _normalise_uri(uri: str, root: Path | None) -> str:
    parsed = urlparse(uri)
    path = unquote(parsed.path if parsed.scheme == "file" else uri)
    if root and Path(path).is_absolute() and Path(path).resolve().is_relative_to(root):
        return Path(path).resolve().relative_to(root).as_posix()
    return path


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Merge findings on the same line for the same weakness (CWE, else rule)."""
    merged: dict[tuple[str, int, str], Finding] = {}
    for f in findings:
        key = (f.path, f.start_line, f.cwes[0] if f.cwes else f.rules[0])
        if key not in merged:
            merged[key] = f.model_copy(update={"id": _fingerprint(key)})
            continue
        kept = merged[key]
        kept.tools = sorted({*kept.tools, *f.tools})
        kept.rules = sorted({*kept.rules, *f.rules})
        kept.cwes = sorted({*kept.cwes, *f.cwes})
        if f.rank > kept.rank:
            kept.level, kept.message = f.level, f.message
    return sorted(merged.values(), key=lambda f: (-f.rank, f.path, f.start_line))


def _fingerprint(key: tuple[str, int, str]) -> str:
    return hashlib.sha256(":".join(map(str, key)).encode()).hexdigest()[:12]
