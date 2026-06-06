# Crypto/PQC Migration Radar - Project Steps

This project is a passive static scanner for crypto migration debt and PQC
readiness. It must stay defensive: no key recovery, no live endpoint testing, no
exploit claims.

## Step 1 - Standalone Project Packaging

Status: completed

- Keep the project independent from `hard-discovery-factory`.
- Add package/test metadata.
- Make `reproduce.ps1` run tests, scan, and verifier from this directory.
- Keep generated reports out of source control.

Exit criteria:

- `python -m pytest` passes.
- `.\reproduce.ps1` writes scanner and verifier outputs.
- CLI scripts have smoke coverage.
- The project can be copied or published independently.

Review result:

- Second-agent review completed.
- Fixed standalone README packaging issue.
- Added install/bootstrap guidance.
- Added CLI smoke tests.
- Verified reproduction with output outside the source tree.
- Removed generated reports and Python caches from the project tree.

## Step 2 - CLI UX and Input Safety

Status: completed

- Add clearer command help and exit codes.
- Add `--fail-on` thresholds for CI use.
- Add optional `--repo-id`.
- Add path traversal and output-directory collision tests.

Review result:

- Second-agent review completed.
- Fixed `--out-dir` existing-file handling.
- Escaped `--repo-id` in DOT graph labels.
- Strengthened verifier path traversal test with an existing outside file.
- Made `reproduce.ps1 -Force` explicit instead of always forcing overwrites.

## Step 3 - Pattern Catalog Externalization

Status: completed

- Move hardcoded patterns into a versioned JSON/YAML catalog.
- Add schema validation for pattern entries.
- Add pattern tests for false positives and false negatives.

Review result:

- Second-agent review completed.
- Added required catalog `version` validation and report metadata.
- Added `--pattern-catalog` to Markdown reproduction command.
- Rejected boolean `confidence` values in catalog validation.
- Verified custom catalog, invalid catalog, and default catalog tests.

## Step 4 - Context Classifier Upgrade

Status: completed

- Improve runtime/test/docs/generated classification.
- Add import/dependency context detection.
- Add lockfile-only downgrade tests.

Review result:

- Added context classes: `runtime`, `test`, `docs`, `example`, `generated`,
  `vendor`, `manifest`, `lockfile`, `unknown`.
- Added dependency inventory and source import/dependency usage context.
- Downgraded docs/test/example/generated/vendor and lockfile-only evidence to
  inventory-only unless runtime evidence is present.
- Added claim-discipline fields to findings and Markdown downgrade wording.
- Verified runtime import, fake test key, docs example, lockfile-only,
  generated/vendor downgrade, and runtime hardcoded material tests.

## Step 5 - Graph and Ranking Upgrade

Status: completed

- Add richer graph edges: imports, depends_on, signs_with, verifies_with.
- Rank migration bottlenecks by file centrality and impact area.
- Produce top review paths, not just grouped pattern findings.

Implementation checkpoint:

- DOT graph edges now distinguish `imports`, `depends_on`, `signs_with`,
  `verifies_with`, `uses_protocol`, and `mentions`.
- JSON/Markdown reports include ranked `review_paths`.
- Runtime lifecycle paths rank above lockfile-only dependency inventory.
- Claim wording remains passive: review paths are prioritization signals, not
  reachability or exploitability claims.

Second-agent review checkpoint:

- Clarified graph edges as inferred static review edges.
- Fixed review-path verdict aggregation when multiple categories share the same
  primitive name.
- Added regression tests for primitive-name collisions, downgrade-heavy docs
  ranking, and claim wording.

## Step 6 - Batch Scanner

Status: completed

- Scan many local repositories.
- Generate cross-repo summary CSV/JSON.
- Identify shared crypto libraries and repeated migration gaps.

Review result:

- Added `batch_crypto_pqc_radar.py` with repeated `--root` and `--roots-file`
  inputs.
- Added batch outputs: `batch_summary.json`, `batch_summary.md`,
  `batch_repositories.csv`, `batch_shared_crypto_signals.csv`, and per-repo
  scanner outputs under `repos/`.
- Batch summary separates runtime review repositories from inventory-only
  repositories.
- Cross-repo wording is defensive: repeated static migration review signal, not
  shared vulnerability or organization-wide blocker.
- Added tests for runtime-vs-inventory split, shared static signals, deterministic
  sorting, missing roots, non-empty output refusal, and CSV/JSON consistency.

## Step 7 - Maintainer Workflow

Status: completed

- Generate verifier-approved maintainer notes only.
- Add markdown templates for internal audit and external disclosure.
- Add wording tests to prevent exploitability claims.

Review result:

- Scanner now writes `internal_review_note.md` only, marked not
  verifier-approved and not sendable.
- Verifier remains the only path that writes `verified_maintainer_note.md`.
- Added `templates/INTERNAL_AUDIT_TEMPLATE.md` and
  `templates/VERIFIED_MAINTAINER_NOTE_TEMPLATE.md`.
- Added wording tests for notes/templates to prevent positive exploitability,
  vulnerability, key-recovery, or attack-path claims.
- `write_reports` removes legacy `maintainer_note.md` outputs when rewriting an
  output directory.

## Step 8 - CI and Release Readiness

Status: completed

- Add lint/type checks.
- Add GitHub Actions or local equivalent.
- Add versioned changelog and release checklist.

Review result:

- Added `quality_gate.py` for compile checks, defensive wording checks, and
  pytest.
- Added package script `crypto-pqc-quality-gate`.
- Added GitHub Actions workflow at `.github/workflows/ci.yml`.
- Added `CHANGELOG.md` and `RELEASE_CHECKLIST.md`.
- `reproduce.ps1` now runs the quality gate before scanner/verifier/batch
  outputs.
