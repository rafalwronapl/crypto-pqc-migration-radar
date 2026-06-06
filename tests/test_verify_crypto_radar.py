from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
WORKSTREAM = HERE.parents[1]
sys.path.insert(0, str(WORKSTREAM))

from crypto_pqc_radar import run  # noqa: E402
from verify_crypto_radar import verify_report, write_verifier_outputs  # noqa: E402


FORBIDDEN_POSITIVE_WORDING = (
    "we can hack",
    "hacked",
    "broken crypto",
    "private keys can be recovered",
    "confirmed vulnerability",
    "attack path",
    "proves vulnerability",
    "proves exploitability",
)


def assert_safe_note_wording(text: str) -> None:
    lowered = " ".join(text.lower().split())
    for phrase in FORBIDDEN_POSITIVE_WORDING:
        assert phrase not in lowered
    assert "not proof of exploitability" in lowered or "does not prove" in lowered


def test_verifier_confirms_runtime_line_evidence(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    (repo / "auth.ts").write_text(
        "import jwt from 'jsonwebtoken';\n"
        "export const token = jwt.sign({}, key, { algorithm: 'RS256' });\n",
        encoding="utf-8",
    )
    run(repo, out)

    result = verify_report(repo, out / "qday_risk_report.json")

    assert result["summary"]["evidence_verified_line"] > 0
    assert any(check["reviewer_verdict"] == "verified_static_finding" for check in result["finding_checks"])


def test_verifier_blocks_missing_line_evidence(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    source = repo / "auth.ts"
    source.write_text("jwt.sign({}, key, { algorithm: 'RS256' });\n", encoding="utf-8")
    run(repo, out)
    source.write_text("// line changed after scan\n", encoding="utf-8")

    result = verify_report(repo, out / "qday_risk_report.json")

    assert any(check["reviewer_verdict"] == "blocked_missing_evidence" for check in result["finding_checks"])


def test_verifier_outputs_markdown_and_json(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    (repo / "README.md").write_text("PQC and hybrid migration are planned.\n", encoding="utf-8")
    run(repo, out)
    result = verify_report(repo, out / "qday_risk_report.json")
    verifier_md = out / "verifier_report.md"

    write_verifier_outputs(result, verifier_md)

    assert verifier_md.exists()
    assert verifier_md.with_suffix(".json").exists()
    assert (out / "downgrade_feedback.json").exists()
    assert (out / "downgrade_feedback.csv").exists()
    assert (out / "verified_maintainer_note.md").exists()
    assert "Crypto/PQC Radar Verifier Report" in verifier_md.read_text(encoding="utf-8")
    assert_safe_note_wording(verifier_md.read_text(encoding="utf-8"))
    assert_safe_note_wording((out / "verified_maintainer_note.md").read_text(encoding="utf-8"))
    feedback = json.loads((out / "downgrade_feedback.json").read_text(encoding="utf-8"))
    assert feedback
    assert {"candidate_id", "status", "nearest_baseline", "why_downgraded", "reusable_lesson", "next_operator_change"}.issubset(feedback[0])


def test_verifier_blocks_path_traversal_evidence(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    out.mkdir()
    (tmp_path / "outside.txt").write_text("RSA outside repo\n", encoding="utf-8")
    report = {
        "repo": {"id": "repo", "path": str(repo)},
        "findings": [
            {
                "finding_id": "CRYPTO-TRAVERSAL",
                "verdict": "migration_review",
                "primitive_or_protocol": "RSA",
                "title": "Traversal test",
                "recommended_next_step": "Review only.",
            }
        ],
        "evidence": [
            {
                "file_path": "../outside.txt",
                "line": 1,
                "matched_text": "RSA",
                "category": "rsa",
                "primitive_or_protocol": "RSA",
                "context_kind": "source",
                "source_kind": "code_or_config",
            }
        ],
        "claim_boundary": "Passive static review.",
    }
    report_path = out / "qday_risk_report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    result = verify_report(repo, report_path)

    assert result["finding_checks"][0]["reviewer_verdict"] == "blocked_missing_evidence"


def test_scanner_internal_note_is_not_maintainer_facing(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    (repo / "auth.js").write_text("jwt.sign({}, privateKey, { algorithm: 'RS256' });\n", encoding="utf-8")

    run(repo, out)

    internal_note = (out / "internal_review_note.md").read_text(encoding="utf-8")
    assert "not verifier-approved" in internal_note
    assert "do not send" in internal_note
    assert not (out / "maintainer_note.md").exists()
    assert_safe_note_wording(internal_note)


def test_markdown_templates_keep_claim_boundary_defensive() -> None:
    templates = [
        WORKSTREAM / "templates" / "INTERNAL_AUDIT_TEMPLATE.md",
        WORKSTREAM / "templates" / "VERIFIED_MAINTAINER_NOTE_TEMPLATE.md",
    ]

    for template in templates:
        text = template.read_text(encoding="utf-8")
        assert_safe_note_wording(text)
        assert "passive static review" in text.lower()
