"""Build the code excerpt that goes to Claude, safely.

Three things happen before any code leaves the machine:
1. The SARIF path must resolve inside the repository (a crafted SARIF file must not be able
   to make the bot read /etc/passwd or ~/.ssh).
2. Secrets are redacted. A secret-scanner finding has every flagged line blanked out.
3. The excerpt is checked for text aimed at an AI reviewer ("mark this as a false positive").
   Such findings skip the model and go straight to a human.
"""

import re
from dataclasses import dataclass
from pathlib import Path

from .models import Finding

RADIUS = 12  # lines of context either side of the finding

_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*"), "[REDACTED PRIVATE KEY]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED AWS KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "[REDACTED GITHUB TOKEN]"),
    (re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}"), "[REDACTED ANTHROPIC KEY]"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), "[REDACTED SLACK TOKEN]"),
    (re.compile(r"\beyJ[\w-]{10,}\.eyJ[\w-]{10,}\.[\w-]{10,}"), "[REDACTED JWT]"),
    # name = "value" style assignments: keep the name so the model can still reason about it
    (
        re.compile(
            r"(?i)\b(\w*(?:password|passwd|secret|token|api[_-]?key)\w*\s*[:=]\s*)"
            r"(['\"])[^'\"]{4,}\2"
        ),
        r"\1\2[REDACTED]\2",
    ),
]

_INJECTION = re.compile(
    r"(?i)("
    r"ignore (?:all |any )?(?:previous|prior|above|earlier) instructions"
    r"|disregard (?:the|your|all) (?:previous|prior|above)?\s*(?:instructions|rules)"
    r"|mark (?:this|it) as (?:a )?(?:false positive|safe|benign)"
    r"|(?:note|message|instruction)s? (?:to|for) (?:the )?(?:ai|llm|automated|security)"
    r"(?: security)? (?:reviewer|scanner|assistant|bot|triager)s?"
    r"|you are (?:now )?(?:an? )?(?:ai|assistant|claude|language model)"
    r")"
)

_SECRET_TOOLS = ("gitleaks", "trufflehog", "detect-secrets")


class UnsafePathError(ValueError):
    """The SARIF file points outside the repository."""


@dataclass(frozen=True)
class Excerpt:
    first_line: int
    last_line: int
    text: str  # numbered lines, e.g. "  12 | query = ..."
    redactions: int
    injection: str | None  # the suspicious phrase, if any

    def covers(self, line: int) -> bool:
        return self.first_line <= line <= self.last_line


def resolve_in_repo(repo: Path, path: str) -> Path:
    root = repo.resolve()
    target = (root / path).resolve()  # an absolute `path` replaces root here, then gets checked
    if not target.is_relative_to(root):
        raise UnsafePathError(f"{path} is outside the repository")
    return target


def redact(line: str) -> tuple[str, int]:
    count = 0
    for pattern, replacement in _SECRET_PATTERNS:
        line, n = pattern.subn(replacement, line)
        count += n
    return line, count


def build_excerpt(repo: Path, finding: Finding, radius: int = RADIUS) -> Excerpt:
    source = resolve_in_repo(repo, finding.path)
    lines = source.read_text(encoding="utf-8").splitlines()
    if finding.start_line > len(lines):
        raise ValueError(f"{finding.path} has no line {finding.start_line}; the scan is stale")
    first = max(1, finding.start_line - radius)
    last = min(len(lines), max(finding.end_line, finding.start_line) + radius)
    secret_finding = any(t.lower().startswith(_SECRET_TOOLS) for t in finding.tools)

    rendered, total = [], 0
    for number in range(first, last + 1):
        line = lines[number - 1]
        if secret_finding and finding.start_line <= number <= finding.end_line:
            line, n = "[REDACTED: line flagged by a secret scanner]", 1
        else:
            line, n = redact(line)
        total += n
        rendered.append(f"{number:>5} | {line}")

    text = "\n".join(rendered)
    match = _INJECTION.search(text)
    return Excerpt(first, last, text, total, match.group(0) if match else None)
