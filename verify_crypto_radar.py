from __future__ import annotations

import argparse
import csv
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


FORBIDDEN_CLAIMS = re.compile(
    r"\b(hack|hacked|exploit(?:able|ed|s)?|broken crypto|private keys? can be recovered|"
    r"production system is vulnerable|signature forgery|decrypt(?:ion|ed)? attack)\b",
    re.IGNORECASE,
)

WEAK_CONTEXTS = {"docs", "test", "fixture", "example", "generated", "vendor", "tooling", "catalog", "lockfile", "unknown"}
RUNTIME_CONTEXTS = {"runtime"}


@dataclass
class EvidenceCheck:
    file_path: str
    line: int
    matched_text: str
    status: str
    context_kind: str
    source_kind: str
    note: str


@dataclass
class FindingCheck:
    finding_id: str
    original_verdict: str
    reviewer_verdict: str
    claim_allowed: bool
    evidence_checked: int
    evidence_passed: int
    notes: list[str]


@dataclass
class DowngradeFeedback:
    candidate_id: str
    status: str
    nearest_baseline: str
    why_downgraded: str
    reusable_lesson: str
    next_operator_change: str


def load_report(report_path: Path) -> dict[str, object]:
    return json.loads(report_path.read_text(encoding="utf-8"))


def line_at(root: Path, rel_path: str, line_no: int) -> str | None:
    if not rel_path or line_no <= 0:
        return None
    path = (root / rel_path).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError:
        return None
    if not path.exists() or not path.is_file():
        return None
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    if line_no > len(lines):
        return None
    return lines[line_no - 1]


def check_evidence(root: Path, evidence: dict[str, object]) -> EvidenceCheck:
    rel_path = str(evidence.get("file_path", ""))
    line_no = int(evidence.get("line", 0) or 0)
    matched_text = str(evidence.get("matched_text", ""))
    context_kind = str(evidence.get("context_kind", ""))
    source_kind = str(evidence.get("source_kind", ""))
    line = line_at(root, rel_path, line_no)
    if line is None:
        return EvidenceCheck(rel_path, line_no, matched_text, "missing_line", context_kind, source_kind, "File or line could not be verified locally.")
    if matched_text and matched_text.lower() not in line.lower():
        return EvidenceCheck(rel_path, line_no, matched_text, "mismatch", context_kind, source_kind, "Line exists but does not contain the recorded match.")
    if context_kind in WEAK_CONTEXTS:
        return EvidenceCheck(rel_path, line_no, matched_text, "weak_context", context_kind, source_kind, "Evidence is docs/test/fixture/example/generated/vendor/tooling/catalog/lockfile context.")
    return EvidenceCheck(rel_path, line_no, matched_text, "verified_line", context_kind, source_kind, "Line-level static evidence verified.")


def reviewer_verdict(finding: dict[str, object], checks: list[EvidenceCheck], report_text: str) -> tuple[str, bool, list[str]]:
    notes: list[str] = []
    original = str(finding.get("verdict", ""))
    if FORBIDDEN_CLAIMS.search(report_text):
        return "rejected_overclaim", False, ["Report text contains forbidden exploitability language."]

    if not checks:
        if original == "pqc_absent_but_relevant":
            return "verified_static_finding", True, ["Migration-gap finding has no direct line evidence by design; claim is limited to scanner absence."]
        return "blocked_missing_evidence", False, ["Finding has no line-level evidence."]

    passed = [check for check in checks if check.status == "verified_line"]
    weak = [check for check in checks if check.status == "weak_context"]
    failed = [check for check in checks if check.status in {"missing_line", "mismatch"}]

    if failed and not passed:
        return "blocked_missing_evidence", False, ["No evidence line could be confirmed locally."]
    if weak and not passed:
        return "verified_inventory_only", True, ["Only weak-context evidence was confirmed; maintainer claim should stay inventory-only."]

    runtime_passed = [check for check in passed if check.context_kind in RUNTIME_CONTEXTS]
    if not runtime_passed:
        return "downgraded_context_weak", True, ["Line evidence exists, but runtime context was not confirmed."]
    if original == "inventory_only":
        return "verified_inventory_only", True, ["Inventory-only static evidence verified."]
    notes.append("Runtime line evidence verified; claim remains passive static review only.")
    return "verified_static_finding", True, notes


def verify_report(root: Path, report_path: Path) -> dict[str, object]:
    report = load_report(report_path)
    root = root.resolve()
    evidence = list(report.get("evidence", []))
    findings = list(report.get("findings", []))
    evidence_by_finding_key: dict[tuple[str, str], list[dict[str, object]]] = {}
    for item in evidence:
        evidence_by_finding_key.setdefault((str(item.get("category", "")), str(item.get("primitive_or_protocol", ""))), []).append(item)

    finding_checks: list[FindingCheck] = []
    evidence_checks: list[EvidenceCheck] = []
    downgrade_feedback: list[DowngradeFeedback] = []
    approved_findings: list[dict[str, object]] = []
    for finding in findings:
        finding_text = json.dumps(
            {
                "title": finding.get("title", ""),
                "recommended_next_step": finding.get("recommended_next_step", ""),
                "verdict": finding.get("verdict", ""),
            },
            ensure_ascii=False,
        )
        primitive = str(finding.get("primitive_or_protocol", ""))
        matching = [
            item
            for items in evidence_by_finding_key.values()
            for item in items
            if str(item.get("primitive_or_protocol", "")) == primitive
        ]
        checks = [check_evidence(root, item) for item in matching[:25]]
        evidence_checks.extend(checks)
        verdict, allowed, notes = reviewer_verdict(finding, checks, finding_text)
        if verdict != "verified_static_finding":
            downgrade_feedback.append(feedback_row_for(finding, verdict, notes))
        finding_checks.append(
            FindingCheck(
                finding_id=str(finding.get("finding_id", "")),
                original_verdict=str(finding.get("verdict", "")),
                reviewer_verdict=verdict,
                claim_allowed=allowed,
                evidence_checked=len(checks),
                evidence_passed=sum(1 for check in checks if check.status == "verified_line"),
                notes=notes,
            )
        )
        if allowed and verdict == "verified_static_finding" and str(finding.get("top_evidence_path", "")):
            approved_findings.append(
                {
                    "finding_id": finding.get("finding_id", ""),
                    "title": finding.get("title", ""),
                    "verdict": finding.get("verdict", ""),
                    "top_evidence_path": finding.get("top_evidence_path", ""),
                    "top_evidence_line": finding.get("top_evidence_line", 0),
                    "recommended_next_step": finding.get("recommended_next_step", ""),
                }
            )

    return {
        "root": str(root),
        "report": str(report_path.resolve()),
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "verifier_version": "0.1.0",
        "summary": {
            "finding_count": len(finding_checks),
            "claim_allowed_count": sum(1 for check in finding_checks if check.claim_allowed),
            "reviewer_verdict_counts": count_verdicts(finding_checks),
            "evidence_checked": len(evidence_checks),
            "evidence_verified_line": sum(1 for check in evidence_checks if check.status == "verified_line"),
        },
        "finding_checks": [asdict(check) for check in finding_checks],
        "evidence_checks": [asdict(check) for check in evidence_checks],
        "downgrade_feedback": [asdict(row) for row in downgrade_feedback],
        "approved_findings": approved_findings,
        "claim_boundary": report.get("claim_boundary", ""),
    }


def count_verdicts(checks: list[FindingCheck]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for check in checks:
        counts[check.reviewer_verdict] = counts.get(check.reviewer_verdict, 0) + 1
    return dict(sorted(counts.items()))


def feedback_row_for(finding: dict[str, object], reviewer_verdict: str, notes: list[str]) -> DowngradeFeedback:
    why = " ".join(notes) if notes else "Verifier did not promote this finding."
    return DowngradeFeedback(
        candidate_id=str(finding.get("finding_id", "")),
        status=reviewer_verdict,
        nearest_baseline=str(finding.get("nearest_baseline", "Passive local pattern inventory.")),
        why_downgraded=why,
        reusable_lesson=str(finding.get("feedback_if_downgraded", "Keep claim tied to verified static line evidence.")),
        next_operator_change=str(finding.get("promotion_requirements", "Require verifier-approved runtime context before maintainer-facing claims.")),
    )


def render_markdown(result: dict[str, object]) -> str:
    summary = result["summary"]
    lines = [
        "# Crypto/PQC Radar Verifier Report",
        "",
        "## Scope",
        "",
        f"- Root: `{result['root']}`",
        f"- Report: `{result['report']}`",
        f"- Verified at: `{result['verified_at']}`",
        "",
        "## Summary",
        "",
        f"- Findings checked: {summary['finding_count']}",
        f"- Claims allowed: {summary['claim_allowed_count']}",
        f"- Evidence rows checked: {summary['evidence_checked']}",
        f"- Verified line evidence: {summary['evidence_verified_line']}",
        f"- Reviewer verdicts: `{json.dumps(summary['reviewer_verdict_counts'], sort_keys=True)}`",
        "",
        "## Finding Checks",
        "",
    ]
    for check in result["finding_checks"]:
        allowed = "allowed" if check["claim_allowed"] else "blocked"
        lines.append(
            f"- `{check['finding_id']}` `{check['reviewer_verdict']}` ({allowed}); "
            f"evidence {check['evidence_passed']}/{check['evidence_checked']}. {' '.join(check['notes'])}"
        )
    lines.extend(["", "## Downgrade Feedback", ""])
    feedback_rows = list(result.get("downgrade_feedback", []))
    if not feedback_rows:
        lines.append("- No downgrade feedback rows.")
    for row in feedback_rows[:10]:
        lines.append(
            f"- `{row['candidate_id']}` `{row['status']}`: {row['why_downgraded']} "
            f"Next: {row['next_operator_change']}"
        )
    lines.extend(
        [
            "",
            "## Boundary",
            "",
            str(result.get("claim_boundary", "")),
            "",
        ]
    )
    return "\n".join(lines)


def write_verifier_outputs(result: dict[str, object], out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_markdown(result), encoding="utf-8")
    json_out = out.with_suffix(".json")
    json_out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    feedback_rows = list(result.get("downgrade_feedback", []))
    feedback_json = out.parent / "downgrade_feedback.json"
    feedback_csv = out.parent / "downgrade_feedback.csv"
    feedback_json.write_text(json.dumps(feedback_rows, indent=2, ensure_ascii=False), encoding="utf-8")
    write_feedback_csv(feedback_csv, feedback_rows)
    note_out = out.parent / "verified_maintainer_note.md"
    note_out.write_text(render_verified_maintainer_note(result), encoding="utf-8")


def write_feedback_csv(path: Path, rows: list[dict[str, object]]) -> None:
    columns = ["candidate_id", "status", "nearest_baseline", "why_downgraded", "reusable_lesson", "next_operator_change"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            writer.writerow({column: row.get(column, "") for column in columns})


def render_verified_maintainer_note(result: dict[str, object]) -> str:
    approved = list(result.get("approved_findings", []))
    lines = [
        "Passive static crypto migration review note:",
        "",
        str(result.get("claim_boundary", "")),
        "",
    ]
    if not approved:
        lines.append("The verifier did not approve any non-inventory maintainer-facing findings in this run.")
    else:
        for finding in approved[:3]:
            lines.append(
                f"- Review `{finding['top_evidence_path']}:{finding['top_evidence_line']}`: "
                f"{finding['title']} (`{finding['verdict']}`)."
            )
        lines.append("")
        lines.append("Suggested next step: verify ownership of these crypto paths and document migration or cleanup decisions.")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify passive Crypto/PQC radar report evidence.")
    parser.add_argument("--root", required=True, type=Path, help="Repository root used by the scanner.")
    parser.add_argument("--report", required=True, type=Path, help="qday_risk_report.json path.")
    parser.add_argument("--out", required=True, type=Path, help="Markdown verifier report output path.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = verify_report(args.root, args.report)
    write_verifier_outputs(result, args.out)
    print(f"Wrote verifier report to {args.out} and {args.out.with_suffix('.json')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
