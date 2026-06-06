from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


DIFF_CLAIM_BOUNDARY = (
    "This diff compares passive static Crypto/PQC radar reports. It reports "
    "migration review evidence deltas, not vulnerability regressions or proof of "
    "runtime reachability."
)

DIFF_COLUMNS = [
    "change_type",
    "key",
    "old_evidence_grade",
    "new_evidence_grade",
    "old_verdict",
    "new_verdict",
    "file_path",
    "line",
    "claim_state",
]


def finding_key(finding: dict[str, object]) -> str:
    return "|".join(
        [
            str(finding.get("primitive_or_protocol", "")),
            str(finding.get("top_evidence_path", "")),
            str(finding.get("top_evidence_line", "")),
            str(finding.get("verdict", "")),
        ]
    )


def load_report(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def diff_reports(old_report: dict[str, object], new_report: dict[str, object]) -> dict[str, object]:
    old_findings = {finding_key(finding): finding for finding in old_report.get("findings", [])}
    new_findings = {finding_key(finding): finding for finding in new_report.get("findings", [])}
    rows: list[dict[str, object]] = []

    for key in sorted(set(new_findings) - set(old_findings)):
        finding = new_findings[key]
        rows.append(row_for("new_static_evidence", key, None, finding))
    for key in sorted(set(old_findings) - set(new_findings)):
        finding = old_findings[key]
        rows.append(row_for("resolved_static_evidence", key, finding, None))
    for key in sorted(set(old_findings) & set(new_findings)):
        old = old_findings[key]
        new = new_findings[key]
        if old.get("evidence_grade") != new.get("evidence_grade") or old.get("suppression_status") != new.get("suppression_status"):
            rows.append(row_for("changed_evidence_grade", key, old, new))

    return {
        "claim_boundary": DIFF_CLAIM_BOUNDARY,
        "what_is_compared": "Finding identity, verdict, evidence grade, suppression status, and cited static location from two scanner JSON reports.",
        "what_is_not_proven": "No vulnerability regression, exploitability, runtime reachability, or migration blocker is proven.",
        "summary": {
            "new_static_evidence": sum(1 for row in rows if row["change_type"] == "new_static_evidence"),
            "resolved_static_evidence": sum(1 for row in rows if row["change_type"] == "resolved_static_evidence"),
            "changed_evidence_grade": sum(1 for row in rows if row["change_type"] == "changed_evidence_grade"),
        },
        "changes": rows,
    }


def row_for(change_type: str, key: str, old: dict[str, object] | None, new: dict[str, object] | None) -> dict[str, object]:
    current = new or old or {}
    return {
        "change_type": change_type,
        "key": key,
        "old_evidence_grade": "" if old is None else old.get("evidence_grade", ""),
        "new_evidence_grade": "" if new is None else new.get("evidence_grade", ""),
        "old_verdict": "" if old is None else old.get("verdict", ""),
        "new_verdict": "" if new is None else new.get("verdict", ""),
        "file_path": current.get("top_evidence_path", ""),
        "line": current.get("top_evidence_line", 0),
        "claim_state": current.get("claim_state", "local_signal"),
    }


def write_outputs(result: dict[str, object], out_json: Path) -> None:
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    csv_path = out_json.with_suffix(".csv")
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=DIFF_COLUMNS)
        writer.writeheader()
        for row in result["changes"]:
            writer.writerow({column: row.get(column, "") for column in DIFF_COLUMNS})
    out_json.with_suffix(".md").write_text(render_markdown(result), encoding="utf-8")


def render_markdown(result: dict[str, object]) -> str:
    summary = result["summary"]
    lines = [
        "# Crypto/PQC Radar Evidence Diff",
        "",
        str(result["claim_boundary"]),
        "",
        f"- what_is_compared: {result['what_is_compared']}",
        f"- what_is_not_proven: {result['what_is_not_proven']}",
        "",
        "## Summary",
        "",
        f"- New static evidence: {summary['new_static_evidence']}",
        f"- Resolved static evidence: {summary['resolved_static_evidence']}",
        f"- Changed evidence grade: {summary['changed_evidence_grade']}",
    ]
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare two passive Crypto/PQC radar JSON reports.")
    parser.add_argument("--old", required=True, type=Path, help="Old qday_risk_report.json.")
    parser.add_argument("--new", required=True, type=Path, help="New qday_risk_report.json.")
    parser.add_argument("--out", required=True, type=Path, help="Output diff JSON path.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = diff_reports(load_report(args.old), load_report(args.new))
    write_outputs(result, args.out)
    print(f"Wrote evidence diff to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
