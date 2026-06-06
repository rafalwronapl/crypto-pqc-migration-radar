from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
CHECKED_TEXT_GLOBS = ("*.md", "templates/*.md")
FORBIDDEN_POSITIVE_CLAIMS = re.compile(
    r"\b(we can hack|can be hacked|hacked|broken crypto|private keys can be recovered|"
    r"confirmed vulnerability|production system is vulnerable|proves vulnerability|proves exploitability|attack path)\b",
    re.IGNORECASE,
)
SAFE_LIST_SECTION = re.compile(r"\b(forbidden|avoid|not allowed|reject maintainer claim|default phrasing)\b", re.IGNORECASE)


def run_command(args: list[str]) -> None:
    result = subprocess.run(args, cwd=ROOT, text=True, check=False)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def checked_text_files() -> list[Path]:
    files: list[Path] = []
    for pattern in CHECKED_TEXT_GLOBS:
        files.extend(ROOT.glob(pattern))
    return sorted(dict.fromkeys(path for path in files if path.is_file()))


def check_defensive_wording() -> None:
    failures: list[str] = []
    for path in checked_text_files():
        safe_list_section = False
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#") and not SAFE_LIST_SECTION.search(stripped):
                safe_list_section = False
            if SAFE_LIST_SECTION.search(stripped):
                safe_list_section = True
            if FORBIDDEN_POSITIVE_CLAIMS.search(line) and not safe_list_section and not is_negated_claim_line(line):
                failures.append(f"{path.relative_to(ROOT)}:{line_no}")
    if failures:
        joined = ", ".join(failures)
        raise SystemExit(f"forbidden positive security claim wording found in: {joined}")


def is_negated_claim_line(line: str) -> bool:
    lowered = line.lower()
    return any(marker in lowered for marker in ("not proof", "does not prove", "does not claim", "not allowed", "forbidden"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Local quality gate for Crypto/PQC Migration Radar.")
    parser.add_argument("--skip-pytest", action="store_true", help="Run compile and wording checks without pytest.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    run_command([sys.executable, "-m", "compileall", "-q", "crypto_pqc_radar.py", "verify_crypto_radar.py", "batch_crypto_pqc_radar.py", "diff_crypto_pqc_radar.py", "benchmark_corpus.py", "quality_gate.py"])
    check_defensive_wording()
    if not args.skip_pytest:
        run_command([sys.executable, "-m", "pytest"])
    print("quality gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
