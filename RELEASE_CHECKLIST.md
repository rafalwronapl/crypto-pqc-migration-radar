# Release Checklist

Use this checklist before publishing or sending reports outside the local
workspace.

## Quality Gate

- Run `python .\quality_gate.py`.
- Run `.\reproduce.ps1 -OutDir <fresh-output-dir> -Force`.
- Confirm generated reports contain `claim_boundary`, `what_is_certified`, and
  `what_is_not_certified` fields where applicable.

## Claim Discipline

- Do not claim exploitability, live vulnerability, key recovery, or production
  reachability from scanner output.
- Treat graph edges as inferred static review edges.
- Treat batch shared signals as repeated static migration review signals, not
  organization-wide blockers.
- Send only `verified_maintainer_note.md`, never `internal_review_note.md`.

## Release Artifacts

- `README.md`
- `CHANGELOG.md`
- `PROJECT_STEPS.md`
- `claim_boundary.md`
- `pattern_catalog.json`
- `crypto_pqc_radar.py`
- `verify_crypto_radar.py`
- `batch_crypto_pqc_radar.py`
- `quality_gate.py`
- `templates/`
- `tests/`
- `.github/workflows/ci.yml`
