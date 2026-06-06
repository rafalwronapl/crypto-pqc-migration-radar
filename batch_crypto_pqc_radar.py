from __future__ import annotations

import argparse
import csv
import json
import shutil
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from crypto_pqc_radar import (
    CLAIM_BOUNDARY,
    DEFAULT_PATTERN_CATALOG,
    build_review_paths,
    dedupe_findings,
    file_sha256,
    pattern_catalog_version,
    repo_id_for,
    scan_repo,
    write_reports,
)


BATCH_CLAIM_BOUNDARY = (
    "This batch report counts repeated passive static crypto/PQC migration review "
    "signals across local repositories. It does not prove shared vulnerability, "
    "runtime reachability, exploitability, or an organization-wide migration blocker."
)
OUTPUT_MARKER = ".crypto-pqc-radar-output"

SUMMARY_COLUMNS = [
    "repo_id",
    "root_path",
    "evidence_count",
    "finding_count",
    "review_finding_count",
    "inventory_only_finding_count",
    "runtime_review_path_count",
    "inventory_only_path_count",
    "evidence_grades",
    "top_review_path",
    "top_review_score",
    "top_review_reason",
]

SHARED_SIGNAL_COLUMNS = [
    "signal",
    "category",
    "repo_count",
    "runtime_review_repos",
    "inventory_only_repos",
    "evidence_count",
    "claim_state",
]


@dataclass
class BatchRepoResult:
    repo_id: str
    root_path: str
    evidence_count: int
    finding_count: int
    review_finding_count: int
    inventory_only_finding_count: int
    runtime_review_path_count: int
    inventory_only_path_count: int
    evidence_grades: str
    top_review_path: str
    top_review_score: float
    top_review_reason: str


def read_roots_file(path: Path) -> list[Path]:
    roots: list[Path] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        roots.append(Path(stripped))
    return roots


def validate_roots(roots: list[Path]) -> list[Path]:
    if not roots:
        raise ValueError("batch scan requires at least one repository root")
    resolved: list[Path] = []
    for root in roots:
        path = root.resolve()
        if not path.exists() or not path.is_dir():
            raise ValueError(f"batch root must be an existing directory: {root}")
        resolved.append(path)
    return sorted(dict.fromkeys(resolved), key=lambda path: str(path).lower())


def run_batch(
    roots: list[Path],
    out_dir: Path,
    pattern_catalog: Path = DEFAULT_PATTERN_CATALOG,
    force: bool = False,
) -> dict[str, object]:
    roots = validate_roots(roots)
    if out_dir.exists() and not out_dir.is_dir():
        raise ValueError(f"--out-dir exists but is not a directory: {out_dir}")
    if out_dir.exists() and any(out_dir.iterdir()):
        if not force:
            raise ValueError(f"--out-dir is not empty; use --force to overwrite batch outputs: {out_dir}")
        if not (out_dir / OUTPUT_MARKER).exists():
            raise ValueError(f"--force refuses to remove an unmarked directory; choose an empty out-dir or one containing {OUTPUT_MARKER}: {out_dir}")
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / OUTPUT_MARKER).write_text("batch_crypto_pqc_radar output directory\n", encoding="utf-8")
    repo_out_dir = out_dir / "repos"
    repo_out_dir.mkdir()

    repo_results: list[BatchRepoResult] = []
    all_evidence: list[dict[str, object]] = []
    all_findings: list[dict[str, object]] = []
    all_review_paths: list[dict[str, object]] = []

    for root in roots:
        repo_id = repo_id_for(root)
        evidence = scan_repo(root, repo_id=repo_id, pattern_catalog=pattern_catalog)
        findings = dedupe_findings(evidence)
        review_paths = build_review_paths(evidence, findings)
        write_reports(root, repo_out_dir / safe_dir_name(repo_id), evidence, findings, repo_id=repo_id, pattern_catalog=pattern_catalog)

        top_path = review_paths[0] if review_paths else {}
        repo_results.append(
            BatchRepoResult(
                repo_id=repo_id,
                root_path=str(root),
                evidence_count=len(evidence),
                finding_count=len(findings),
                review_finding_count=sum(1 for finding in findings if finding.verdict != "inventory_only"),
                inventory_only_finding_count=sum(1 for finding in findings if finding.verdict == "inventory_only"),
                runtime_review_path_count=sum(1 for path in review_paths if not bool(path["downgrade_only"])),
                inventory_only_path_count=sum(1 for path in review_paths if bool(path["downgrade_only"])),
                evidence_grades=";".join(sorted({finding.evidence_grade for finding in findings})),
                top_review_path=str(top_path.get("file_path", "")),
                top_review_score=float(top_path.get("rank_score", 0.0) or 0.0),
                top_review_reason=str(top_path.get("review_reason", "")),
            )
        )
        all_evidence.extend(asdict(item) for item in evidence)
        all_findings.extend(asdict(item) for item in findings)
        all_review_paths.extend({"repo_id": repo_id, **path} for path in review_paths)

    repo_rows = [asdict(result) for result in sorted(repo_results, key=lambda result: result.repo_id)]
    shared_signals = build_shared_signals(all_evidence)
    report = {
        "batch": {
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "repo_count": len(repo_rows),
            "out_dir": str(out_dir.resolve()),
        },
        "pattern_catalog": {
            "path": str(pattern_catalog),
            "version": pattern_catalog_version(pattern_catalog),
            "sha256": file_sha256(pattern_catalog),
        },
        "claim_boundary": BATCH_CLAIM_BOUNDARY,
        "single_repo_claim_boundary": CLAIM_BOUNDARY,
        "what_is_counted": "Repeated passive static evidence rows, finding verdicts, context classes, and inferred static review paths across local repository roots.",
        "what_is_not_proven": "No shared vulnerability, exploitability, production reachability, key validity, or organization-wide migration blocker is proven.",
        "repositories": repo_rows,
        "shared_crypto_signals": shared_signals,
        "top_review_paths": sorted(all_review_paths, key=lambda path: (-float(path["rank_score"]), str(path["repo_id"]), str(path["file_path"])))[:25],
    }
    write_csv(out_dir / "batch_repositories.csv", repo_rows, SUMMARY_COLUMNS)
    write_csv(out_dir / "batch_shared_crypto_signals.csv", shared_signals, SHARED_SIGNAL_COLUMNS)
    (out_dir / "batch_summary.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / "batch_summary.md").write_text(render_batch_markdown(report), encoding="utf-8")
    return report


def build_shared_signals(evidence: list[dict[str, object]]) -> list[dict[str, object]]:
    by_signal: dict[tuple[str, str], list[dict[str, object]]] = {}
    for item in evidence:
        category = str(item.get("category", ""))
        if category not in {"crypto_library", "rsa", "ecdsa", "secp256k1", "ed25519", "jwt", "tls", "ssh_key", "pqc_signal"}:
            continue
        signal = str(item.get("matched_text", "")).lower()
        if not signal:
            continue
        by_signal.setdefault((category, signal), []).append(item)

    rows: list[dict[str, object]] = []
    for (category, signal), items in by_signal.items():
        repos = sorted({str(item.get("repo_id", "")) for item in items})
        runtime_repos = sorted({str(item.get("repo_id", "")) for item in items if str(item.get("context_kind", "")) == "runtime"})
        inventory_only_repos = sorted(set(repos) - set(runtime_repos))
        if len(repos) < 2:
            continue
        rows.append(
            {
                "signal": signal,
                "category": category,
                "repo_count": len(repos),
                "runtime_review_repos": ";".join(runtime_repos),
                "inventory_only_repos": ";".join(inventory_only_repos),
                "evidence_count": len(items),
                "claim_state": "local_signal",
            }
        )
    return sorted(rows, key=lambda row: (-int(row["repo_count"]), str(row["category"]), str(row["signal"])))


def render_batch_markdown(report: dict[str, object]) -> str:
    batch = report["batch"]
    lines = [
        "# Crypto/PQC Batch Migration Radar Report",
        "",
        "## Scope",
        "",
        str(report["claim_boundary"]),
        "",
        f"- Repositories scanned: {batch['repo_count']}",
        f"- Scan timestamp: `{batch['scan_timestamp']}`",
        "",
        "## Claim Discipline",
        "",
        f"- what_is_counted: {report['what_is_counted']}",
        f"- what_is_not_proven: {report['what_is_not_proven']}",
        "",
        "## Repository Summary",
        "",
    ]
    for repo in report["repositories"]:
        lines.append(
            f"- `{repo['repo_id']}` evidence {repo['evidence_count']} findings {repo['finding_count']} "
            f"runtime_review_paths {repo['runtime_review_path_count']} inventory_only_paths {repo['inventory_only_path_count']} "
            f"grades `{repo['evidence_grades']}`"
        )
    lines.extend(["", "## Shared Static Signals", ""])
    shared = list(report["shared_crypto_signals"])
    if not shared:
        lines.append("- No repeated static crypto signals across repositories.")
    for row in shared[:20]:
        lines.append(
            f"- `{row['signal']}` `{row['category']}` in {row['repo_count']} repos; "
            f"runtime repos `{row['runtime_review_repos']}` inventory-only repos `{row['inventory_only_repos']}`"
        )
    lines.extend(["", "## Top Inferred Static Review Paths", ""])
    for path in list(report["top_review_paths"])[:10]:
        lines.append(
            f"- `{path['repo_id']}` `{path['file_path']}` score {path['rank_score']}: "
            f"{path['review_reason']}"
        )
    return "\n".join(lines)


def write_csv(path: Path, rows: list[dict[str, object]], columns: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            writer.writerow({column: row.get(column, "") for column in columns})


def safe_dir_name(value: str) -> str:
    return "".join(char if char.isalnum() or char in {"-", "_", "."} else "_" for char in value)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Batch passive Crypto/PQC migration radar.")
    parser.add_argument("--root", action="append", default=[], type=Path, help="Repository root to scan. Repeat for multiple roots.")
    parser.add_argument("--roots-file", type=Path, help="Text file containing one repository root per line.")
    parser.add_argument("--out-dir", required=True, type=Path, help="Directory for batch outputs.")
    parser.add_argument("--pattern-catalog", default=DEFAULT_PATTERN_CATALOG, type=Path, help="JSON pattern catalog to load.")
    parser.add_argument("--force", action="store_true", help="Allow replacing a non-empty batch output directory.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    roots = list(args.root)
    if args.roots_file:
        if not args.roots_file.exists() or not args.roots_file.is_file():
            raise SystemExit(f"--roots-file must be an existing file: {args.roots_file}")
        roots.extend(read_roots_file(args.roots_file))
    try:
        report = run_batch(roots, args.out_dir, pattern_catalog=args.pattern_catalog, force=args.force)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    print(f"Wrote batch report for {report['batch']['repo_count']} repositories to {args.out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
