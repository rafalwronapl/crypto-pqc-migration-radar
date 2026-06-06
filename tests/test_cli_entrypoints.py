from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


WORKSTREAM = Path(__file__).resolve().parents[1]


def test_scanner_and_verifier_cli_scripts(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    (repo / "auth.js").write_text("jwt.sign({}, key, { algorithm: 'RS256' });\n", encoding="utf-8")

    scan = subprocess.run(
        [
            sys.executable,
            str(WORKSTREAM / "crypto_pqc_radar.py"),
            "--root",
            str(repo),
            "--out-dir",
            str(out),
            "--repo-id",
            "cli-repo",
        ],
        cwd=WORKSTREAM,
        text=True,
        capture_output=True,
        check=False,
    )

    assert scan.returncode == 0, scan.stderr
    assert (out / "qday_risk_report.json").exists()
    report = json.loads((out / "qday_risk_report.json").read_text(encoding="utf-8"))
    assert report["repo"]["id"] == "cli-repo"

    verify = subprocess.run(
        [
            sys.executable,
            str(WORKSTREAM / "verify_crypto_radar.py"),
            "--root",
            str(repo),
            "--report",
            str(out / "qday_risk_report.json"),
            "--out",
            str(out / "verifier_report.md"),
        ],
        cwd=WORKSTREAM,
        text=True,
        capture_output=True,
        check=False,
    )

    assert verify.returncode == 0, verify.stderr
    assert (out / "verifier_report.md").exists()
    assert (out / "verified_maintainer_note.md").exists()
    verifier = json.loads((out / "verifier_report.json").read_text(encoding="utf-8"))
    assert verifier["summary"]["evidence_verified_line"] > 0


def test_cli_help_commands() -> None:
    for script in ("crypto_pqc_radar.py", "verify_crypto_radar.py", "batch_crypto_pqc_radar.py", "quality_gate.py", "diff_crypto_pqc_radar.py", "benchmark_corpus.py"):
        result = subprocess.run(
            [sys.executable, str(WORKSTREAM / script), "--help"],
            cwd=WORKSTREAM,
            text=True,
            capture_output=True,
            check=False,
        )

        assert result.returncode == 0
        assert "usage:" in result.stdout.lower()


def test_scanner_refuses_non_empty_out_dir_without_force(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    out.mkdir()
    (out / "existing.txt").write_text("keep\n", encoding="utf-8")
    (repo / "auth.js").write_text("jwt.sign({}, key, { algorithm: 'RS256' });\n", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            str(WORKSTREAM / "crypto_pqc_radar.py"),
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


def test_scanner_refuses_out_dir_that_is_file(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out.txt"
    repo.mkdir()
    out.write_text("not a directory\n", encoding="utf-8")
    (repo / "auth.js").write_text("jwt.sign({}, key, { algorithm: 'RS256' });\n", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            str(WORKSTREAM / "crypto_pqc_radar.py"),
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
    assert "not a directory" in result.stderr


def test_repo_id_is_escaped_in_dot_graph(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    (repo / "auth.js").write_text("jwt.sign({}, key, { algorithm: 'RS256' });\n", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            str(WORKSTREAM / "crypto_pqc_radar.py"),
            "--root",
            str(repo),
            "--out-dir",
            str(out),
            "--repo-id",
            'repo "quoted" \\ test',
        ],
        cwd=WORKSTREAM,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    dot = (out / "crypto_graph.dot").read_text(encoding="utf-8")
    assert 'repo \\"quoted\\" \\\\ test' in dot


def test_fail_on_review_returns_ci_failure(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    (repo / "auth.js").write_text("jwt.sign({}, key, { algorithm: 'RS256' });\n", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            str(WORKSTREAM / "crypto_pqc_radar.py"),
            "--root",
            str(repo),
            "--out-dir",
            str(out),
            "--fail-on",
            "review",
        ],
        cwd=WORKSTREAM,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 3


def test_invalid_pattern_catalog_returns_clean_error(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    catalog = tmp_path / "bad.json"
    repo.mkdir()
    (repo / "auth.js").write_text("jwt.sign({}, key, { algorithm: 'RS256' });\n", encoding="utf-8")
    catalog.write_text('{"patterns": []}', encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            str(WORKSTREAM / "crypto_pqc_radar.py"),
            "--root",
            str(repo),
            "--out-dir",
            str(out),
            "--pattern-catalog",
            str(catalog),
        ],
        cwd=WORKSTREAM,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "pattern catalog" in result.stderr
