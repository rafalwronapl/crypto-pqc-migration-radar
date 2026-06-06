# Next Steps

The original `PROJECT_STEPS.md` roadmap is complete. Continue as an evidence
ledger rather than a generic crypto scanner.

## Step 9 - Evidence Ledger Hardening

Status: completed

- Add `evidence_grade`, `downgrade_reason`, and `promotion_requirements`.
- Aggregate evidence grades in batch outputs.
- Keep grades separate from vulnerability severity.

Review result:

- Finding CSV/JSON/Markdown now includes evidence grade, downgrade reason, and
  promotion requirements.
- Batch repository summary aggregates evidence grades.
- Tests cover weak-context inventory, hardcoded verifier-required findings, and
  report output fields.

## Step 10 - Interoperable Exports

Status: completed

- Add SARIF output for scanner findings.
- Keep SARIF messages claim-disciplined and verifier-gated.
- Add tests for schema shape and forbidden wording.

Review result:

- Added `crypto_findings.sarif` SARIF 2.1.0 output.
- SARIF results include evidence grade, downgrade reason, promotion
  requirements, and claim boundary properties.
- Tests cover SARIF shape and defensive message wording.

## Step 11 - Import Parser Upgrade

Status: completed

- Replace simple import regexes with lightweight language-aware extraction for
  Python, JavaScript/TypeScript, Go, Rust, and Java.
- Keep fallback regex for unknown languages.
- Add tests showing imports/dependencies are review edges, not reachability
  proof.

Review result:

- Added lightweight language-aware import detection for Python,
  JavaScript/TypeScript, Go, Rust, Java/Kotlin, and C/C++ include lines.
- Kept regex fallback for unknown languages.
- Added tests for multi-language import dependency usage and comment-only
  mentions.

## Step 12 - Baseline Corpus

Status: completed

- Add small synthetic corpus fixtures covering runtime, docs, tests, vendor,
  generated, manifest, lockfile, and batch repeated signals.
- Track expected evidence grades and downgrades.

Review result:

- Added `tests/fixtures/corpus` with runtime, docs-only, lockfile-only, and
  test-fixture repositories.
- Added `expected_corpus.json`.
- Added regression test for expected contexts, verdicts, and evidence grades.

## Step 13 - Verifier Feedback Ledger

Status: completed

- Emit machine-readable downgrade feedback rows from verifier checks.
- Include candidate id, status, nearest baseline, why downgraded, reusable
  lesson, and next operator change.
- Feed this into batch summaries without making discovery claims.

Review result:

- Verifier JSON includes `downgrade_feedback`.
- Verifier output writes `downgrade_feedback.csv` and
  `downgrade_feedback.json`.
- Feedback rows include candidate id, status, nearest baseline, downgrade
  reason, reusable lesson, and next operator change.

## Step 14 - Suppression And Allowlist File

Status: completed

- Add a local suppression file for known docs/test/vendor inventory findings.
- Suppressions must require reason, owner, and expiry.
- Suppression must not delete raw evidence.

Review result:

- Added `--suppressions` JSON input to the scanner.
- Suppression entries require match object plus reason, owner, and expiry.
- Suppressions mark findings but preserve raw evidence and SARIF/report data.
- Tests cover valid suppression, raw evidence preservation, and invalid
  suppression rejection.

## Step 15 - Evidence Diff

Status: completed

- Compare two scanner JSON reports.
- Show new, resolved, and changed evidence grades.
- Keep output as migration review delta, not vulnerability regression.

Review result:

- Added `diff_crypto_pqc_radar.py`.
- Diff output writes JSON, CSV, and Markdown.
- Tests cover new, resolved, and changed evidence grade rows plus defensive
  wording.

## Step 16 - Corpus Expansion

Status: completed

- Add more language fixtures and dependency manifests.
- Add expected SARIF and batch summary shape tests.

Review result:

- Added corpus SARIF shape test.
- Added corpus batch summary shape test.
- Corpus now guards single-repo, SARIF, and batch behavior.
