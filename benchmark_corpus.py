from __future__ import annotations

import argparse
import json
from pathlib import Path

from crypto_pqc_radar import dedupe_findings, scan_repo


DEFAULT_CORPUS = Path(__file__).with_name("tests") / "fixtures" / "corpus"


def load_labels(corpus: Path) -> dict[str, bool]:
    data = json.loads((corpus / "benchmark_labels.json").read_text(encoding="utf-8"))
    labels = data.get("labels")
    if not isinstance(labels, dict) or not labels:
        raise ValueError("benchmark_labels.json must contain non-empty object 'labels'")
    return {str(name): bool(value) for name, value in labels.items()}


def predict_runtime_review(repo_root: Path) -> bool:
    evidence = scan_repo(repo_root)
    findings = dedupe_findings(evidence)
    return any(finding.verdict != "inventory_only" and finding.top_context_kind == "runtime" for finding in findings)


def run_benchmark(corpus: Path = DEFAULT_CORPUS) -> dict[str, object]:
    labels = load_labels(corpus)
    rows: list[dict[str, object]] = []
    tp = fp = tn = fn = 0
    for fixture_name, expected in sorted(labels.items()):
        predicted = predict_runtime_review(corpus / fixture_name)
        if predicted and expected:
            tp += 1
        elif predicted and not expected:
            fp += 1
        elif not predicted and not expected:
            tn += 1
        else:
            fn += 1
        rows.append({"fixture": fixture_name, "expected": expected, "predicted": predicted})
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    return {
        "task": "repo_has_runtime_migration_review_target",
        "claim_boundary": "Synthetic corpus benchmark for scanner behavior; not a real-world accuracy claim.",
        "summary": {
            "true_positive": tp,
            "false_positive": fp,
            "true_negative": tn,
            "false_negative": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
        },
        "rows": rows,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark scanner precision/recall on the labeled synthetic corpus.")
    parser.add_argument("--corpus", default=DEFAULT_CORPUS, type=Path, help="Corpus directory containing benchmark_labels.json.")
    parser.add_argument("--out", type=Path, help="Optional JSON output path.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = run_benchmark(args.corpus)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
