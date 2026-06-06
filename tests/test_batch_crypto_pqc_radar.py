from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
WORKSTREAM = HERE.parents[1]
sys.path.insert(0, str(WORKSTREAM))
CORPUS = WORKSTREAM / "tests" / "fixtures" / "corpus"

from batch_crypto_pqc_radar import BATCH_CLAIM_BOUNDARY, run_batch  # noqa: E402


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_batch_scanner_separates_runtime_review_and_inventory_only_repos(tmp_path: Path) -> None:
    runtime_repo = tmp_path / "runtime-repo"
    lockfile_repo = tmp_path / "lockfile-repo"
    out = tmp_path / "batch-out"
    runtime_repo.mkdir()
    lockfile_repo.mkdir()
    (runtime_repo / "auth.js").write_text("jwt.sign({}, privateKey, { algorithm: 'RS256' });\n", encoding="utf-8")
    (lockfile_repo / "Cargo.lock").write_text('[[package]]\nname = "rsa"\nversion = "0.9.0"\n', encoding="utf-8")

    report = run_batch([runtime_repo, lockfile_repo], out)

    assert report["claim_boundary"] == BATCH_CLAIM_BOUNDARY
    assert "what_is_counted" in report
    assert "what_is_not_proven" in report
    by_path = {Path(row["root_path"]).name: row for row in report["repositories"]}
    assert by_path["runtime-repo"]["runtime_review_path_count"] > 0
    assert by_path["runtime-repo"]["evidence_grades"]
    assert by_path["lockfile-repo"]["runtime_review_path_count"] == 0
    assert by_path["lockfile-repo"]["inventory_only_path_count"] > 0
    assert (out / "batch_summary.json").exists()
    assert (out / "batch_repositories.csv").exists()
    assert (out / "batch_shared_crypto_signals.csv").exists()
    assert (out / "repos").is_dir()


def test_batch_shared_signals_split_runtime_and_inventory_only(tmp_path: Path) -> None:
    runtime_repo = tmp_path / "runtime"
    inventory_repo = tmp_path / "inventory"
    out = tmp_path / "batch"
    runtime_repo.mkdir()
    inventory_repo.mkdir()
    (runtime_repo / "auth.js").write_text("const rsa = require('rsa'); sign(payload, privateKey, rsa);\n", encoding="utf-8")
    (inventory_repo / "package-lock.json").write_text('{"packages":{"node_modules/rsa":{"name":"rsa","version":"1.0.0"}}}', encoding="utf-8")

    report = run_batch([runtime_repo, inventory_repo], out)

    shared = [row for row in report["shared_crypto_signals"] if row["signal"] == "rsa"]
    assert shared
    assert shared[0]["runtime_review_repos"]
    assert shared[0]["inventory_only_repos"]
    markdown = (out / "batch_summary.md").read_text(encoding="utf-8").lower()
    assert "does not prove shared vulnerability" in markdown
    assert "proves shared vulnerability" not in markdown


def test_batch_top_paths_sort_ties_deterministically(tmp_path: Path) -> None:
    repo_b = tmp_path / "b-repo"
    repo_a = tmp_path / "a-repo"
    out = tmp_path / "batch"
    repo_b.mkdir()
    repo_a.mkdir()
    (repo_b / "auth.js").write_text("jwt.sign({}, privateKey, { algorithm: 'RS256' });\n", encoding="utf-8")
    (repo_a / "auth.js").write_text("jwt.sign({}, privateKey, { algorithm: 'RS256' });\n", encoding="utf-8")

    report = run_batch([repo_b, repo_a], out)

    top = report["top_review_paths"][:2]
    assert [path["repo_id"] for path in top] == sorted(path["repo_id"] for path in top)


def test_batch_cli_rejects_missing_root_from_roots_file(tmp_path: Path) -> None:
    roots_file = tmp_path / "roots.txt"
    out = tmp_path / "out"
    roots_file.write_text(str(tmp_path / "missing") + "\n", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            str(WORKSTREAM / "batch_crypto_pqc_radar.py"),
            "--roots-file",
            str(roots_file),
            "--out-dir",
            str(out),
        ],
        cwd=WORKSTREAM,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "existing directory" in result.stderr


def test_batch_cli_refuses_non_empty_out_dir_without_force(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    out.mkdir()
    (out / "keep.txt").write_text("keep\n", encoding="utf-8")
    (repo / "auth.js").write_text("jwt.sign({}, key, { algorithm: 'RS256' });\n", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            str(WORKSTREAM / "batch_crypto_pqc_radar.py"),
            "--root",
            str(repo),
            "--out-dir",
            str(out),
        ],
        cwd=WORKSTREAM,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "not empty" in result.stderr


def test_batch_force_refuses_unmarked_non_empty_out_dir(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "important"
    repo.mkdir()
    out.mkdir()
    (out / "keep.txt").write_text("keep\n", encoding="utf-8")
    (repo / "auth.js").write_text("jwt.sign({}, key, { algorithm: 'RS256' });\n", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            str(WORKSTREAM / "batch_crypto_pqc_radar.py"),
            "--root",
            str(repo),
            "--out-dir",
            str(out),
            "--force",
        ],
        cwd=WORKSTREAM,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "unmarked directory" in result.stderr
    assert (out / "keep.txt").exists()


def test_batch_force_allows_marked_output_dir(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    out.mkdir()
    (out / ".crypto-pqc-radar-output").write_text("batch output\n", encoding="utf-8")
    (out / "old.txt").write_text("old\n", encoding="utf-8")
    (repo / "auth.js").write_text("jwt.sign({}, key, { algorithm: 'RS256' });\n", encoding="utf-8")

    run_batch([repo], out, force=True)

    assert not (out / "old.txt").exists()
    assert (out / ".crypto-pqc-radar-output").exists()
    assert (out / "batch_summary.json").exists()


def test_batch_json_and_csv_are_consistent(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    (repo / "auth.js").write_text("jwt.verify(token, publicKey, { algorithms: ['RS256'] });\n", encoding="utf-8")

    run_batch([repo], out)

    report = json.loads((out / "batch_summary.json").read_text(encoding="utf-8"))
    repository_rows = rows(out / "batch_repositories.csv")
    assert len(report["repositories"]) == len(repository_rows) == 1
    assert report["repositories"][0]["repo_id"] == repository_rows[0]["repo_id"]
    assert repository_rows[0]["evidence_grades"]


def test_baseline_corpus_batch_summary_shape(tmp_path: Path) -> None:
    roots = [path for path in (CORPUS).iterdir() if path.is_dir()]
    out = tmp_path / "batch"

    report = run_batch(roots, out)

    assert report["batch"]["repo_count"] == len(roots)
    assert "what_is_counted" in report
    assert "what_is_not_proven" in report
    assert (out / "batch_summary.json").exists()
    assert (out / "batch_repositories.csv").exists()
    assert any(row["inventory_only_path_count"] > 0 for row in report["repositories"])
    assert any(row["runtime_review_path_count"] > 0 for row in report["repositories"])
