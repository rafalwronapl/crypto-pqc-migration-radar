# Project State

Status: closed for the current roadmap.

Closed at: 2026-06-06

## Completed Scope

- Passive single-repository Crypto/PQC migration radar.
- Context-aware evidence classifier.
- Evidence ledger fields and defensive claim discipline.
- Inferred static graph review paths.
- Batch scanner for repeated local static migration review signals.
- Verifier-gated maintainer workflow.
- SARIF export.
- CBOM-style export.
- Evidence diff.
- Suppression marking without raw evidence deletion.
- Baseline corpus regression tests.
- Labeled synthetic corpus precision/recall benchmark.
- Self-scan hygiene for catalog/tooling/fixture evidence.
- Local quality gate and CI workflow.

## Final Claim

This project is a passive static crypto/PQC migration evidence ledger. It
prioritizes review targets and records downgrade/promotion requirements. It does
not prove exploitability, runtime reachability, key validity, production
vulnerability, or organization-wide migration blockers.

## Verification

Latest local verification:

- `python -m pytest`: 51 passed.
- `python .\quality_gate.py`: passed.
- `.\reproduce.ps1 -Force`: passed.

## Closure Criteria

- `PROJECT_STEPS.md` steps 1-8 are completed.
- `NEXT_STEPS.md` steps 9-16 are completed.
- Known self-scan false positives from scanner catalogs/tooling/fixtures are
  downgraded, not removed.
- Generated reports are excluded from source control by `.gitignore`.
- Release checklist, changelog, templates, CI workflow, and reproducibility
  script are present.
