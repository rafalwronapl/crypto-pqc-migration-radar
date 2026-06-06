from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
WORKSTREAM = HERE.parents[1]
sys.path.insert(0, str(WORKSTREAM))

from diff_crypto_pqc_radar import diff_reports, write_outputs  # noqa: E402


def finding(path: str, grade: str, verdict: str = "migration_review") -> dict[str, object]:
    return {
        "primitive_or_protocol": "JWT",
        "top_evidence_path": path,
        "top_evidence_line": 1,
        "verdict": verdict,
        "evidence_grade": grade,
        "suppression_status": "active",
        "claim_state": "local_signal",
    }


def test_diff_reports_new_resolved_and_changed_evidence_grades(tmp_path: Path) -> None:
    old = {"findings": [finding("old.js", "runtime_static_lifecycle_signal"), finding("changed.js", "weak_context_inventory")]}
    new = {"findings": [finding("new.js", "runtime_static_lifecycle_signal"), finding("changed.js", "runtime_static_lifecycle_signal")]}

    result = diff_reports(old, new)

    assert result["summary"]["new_static_evidence"] == 1
    assert result["summary"]["resolved_static_evidence"] == 1
    assert result["summary"]["changed_evidence_grade"] == 1
    assert "what_is_not_proven" in result
    assert "vulnerability regression" in result["claim_boundary"]

    out = tmp_path / "diff.json"
    write_outputs(result, out)

    assert out.exists()
    assert out.with_suffix(".csv").exists()
    assert out.with_suffix(".md").exists()
    markdown = out.with_suffix(".md").read_text(encoding="utf-8").lower()
    assert "not vulnerability regressions" in markdown
    assert "proof of runtime reachability" in markdown
