import json
from pathlib import Path

import pytest

from triage_bot.sarif import SarifError, load_findings

from .conftest import DATA, ROOT


def test_bandit_sarif_is_parsed_and_merged():
    findings = load_findings([DATA / "bandit.sarif"])
    # 20 Bandit results; B603 and B607 flag the same line for CWE-78 and merge into one.
    assert len(findings) == 19
    df = next(f for f in findings if f.path == "benchmark/app/shell.py" and f.start_line == 12)
    assert df.rules == ["B603", "B607"]
    assert df.cwes == ["CWE-78"]


def test_findings_are_sorted_most_severe_first():
    findings = load_findings([DATA / "bandit.sarif"])
    ranks = [f.rank for f in findings]
    assert ranks == sorted(ranks, reverse=True)
    assert findings[0].level == "error"


def test_missing_level_defaults_to_warning():
    findings = load_findings([DATA / "bandit.sarif"])
    sql = next(f for f in findings if "B608" in f.rules)
    assert sql.level == "warning"


def test_same_issue_from_two_tools_merges_and_keeps_highest_level():
    findings = load_findings([DATA / "multi.sarif"])
    shell = [f for f in findings if f.path == "benchmark/app/shell.py"]
    assert len(shell) == 1
    assert shell[0].tools == ["Bandit", "Semgrep OSS"]
    assert shell[0].level == "error"  # Semgrep's rule default beats Bandit's warning
    assert shell[0].message == "subprocess call with shell=True"


def test_results_without_location_are_skipped_and_bad_levels_normalised():
    findings = load_findings([DATA / "multi.sarif"])
    assert len(findings) == 2
    leak = next(f for f in findings if f.tools == ["Gitleaks"])
    assert leak.level == "warning"
    assert leak.cwes == []


def test_fingerprints_are_stable():
    first = load_findings([DATA / "bandit.sarif"])
    second = load_findings([DATA / "bandit.sarif"])
    assert [f.id for f in first] == [f.id for f in second]
    assert len({f.id for f in first}) == len(first)


def test_absolute_paths_inside_repo_become_relative(tmp_path: Path):
    sarif = {
        "runs": [
            {
                "tool": {"driver": {"name": "X"}},
                "results": [
                    {
                        "ruleId": "R1",
                        "message": {"text": "m"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": (ROOT / "benchmark/app/db.py").as_uri()
                                    },
                                    "region": {"startLine": 7},
                                }
                            }
                        ],
                    }
                ],
            }
        ]
    }
    path = tmp_path / "abs.sarif"
    path.write_text(json.dumps(sarif))
    [finding] = load_findings([path], repo=ROOT)
    assert finding.path == "benchmark/app/db.py"


@pytest.mark.parametrize("content", ["not json", '{"version": "2.1.0"}', "[]"])
def test_invalid_files_raise(tmp_path: Path, content: str):
    path = tmp_path / "bad.sarif"
    path.write_text(content)
    with pytest.raises(SarifError):
        load_findings([path])


def test_missing_file_raises(tmp_path: Path):
    with pytest.raises(SarifError):
        load_findings([tmp_path / "nope.sarif"])
