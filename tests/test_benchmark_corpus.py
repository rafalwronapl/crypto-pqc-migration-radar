from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
WORKSTREAM = HERE.parents[1]
sys.path.insert(0, str(WORKSTREAM))

from benchmark_corpus import run_benchmark  # noqa: E402


def test_labeled_corpus_precision_recall_is_computed(tmp_path: Path) -> None:
    result = run_benchmark(WORKSTREAM / "tests" / "fixtures" / "corpus")

    assert result["task"] == "repo_has_runtime_migration_review_target"
    assert result["claim_boundary"] == "Synthetic corpus benchmark for scanner behavior; not a real-world accuracy claim."
    assert result["summary"]["precision"] >= 0.99
    assert result["summary"]["recall"] >= 0.99
    assert len(result["rows"]) == 4

    out = tmp_path / "benchmark.json"
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    assert out.exists()
