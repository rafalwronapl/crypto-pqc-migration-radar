# Crypto/PQC Migration Radar

[![CI](https://github.com/rafalwronapl/crypto-pqc-migration-radar/actions/workflows/ci.yml/badge.svg)](https://github.com/rafalwronapl/crypto-pqc-migration-radar/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](pyproject.toml)

Passive static scanner for cryptography migration debt and post-quantum
readiness.

The tool scans local source, config, dependency, CI, and documentation files. It
emits line-level evidence for RSA, ECDSA, secp256k1, Ed25519, JWT, TLS, SSH key
material, crypto libraries, and PQC/hybrid migration signals.

The distinguishing design is an evidence ledger: each finding carries context
downgrades, evidence grade, claim boundary, and promotion requirements before it
can become a maintainer-facing note.

Self-scan hygiene is explicit: pattern catalogs, scanner tooling, and synthetic
fixtures are kept as raw evidence but downgraded as `catalog`, `tooling`, or
`fixture` context instead of application runtime evidence.

It does not test live systems, recover keys, forge signatures, decrypt data,
brute force credentials, or claim exploitability.

## Run In 60 Seconds

```powershell
python -m pip install -e ".[test]"
python .\quality_gate.py
python .\crypto_pqc_radar.py --root . --out-dir .\reports\self_scan --repo-id self --force
```

Open `reports/self_scan/qday_risk_report.md` or the JSON/SARIF outputs to
inspect the evidence ledger from a local self-scan.

## Why This Matters

Crypto migration work usually starts with messy evidence: source snippets,
lockfiles, CI config, documentation, test fixtures, and ambiguous library names.
Turning those signals directly into vulnerability claims creates noise.

This scanner keeps the first pass conservative. It records line-level evidence,
downgrades catalog/tooling/fixture context, and requires promotion criteria
before a finding becomes maintainer-facing migration advice.

## Report Confidentiality

Generated reports include file paths, matched text, and short source snippets.
Do not publish reports from private repositories unless you have reviewed and
redacted them. Treat `reports/`, `qday_risk_report.json`, evidence JSONL, SARIF,
CBOM, and CSV outputs as potentially sensitive audit artifacts.

## Quick Start

Install test dependencies in editable mode:

```powershell
python -m pip install -e ".[test]"
```

Run tests and a full scan/verify cycle:

```powershell
python -m pytest
.\reproduce.ps1 -Root C:\path\to\repo -OutDir .\reports\repo_crypto_radar
```

Run the local release quality gate:

```powershell
python .\quality_gate.py
```

Run the labeled synthetic corpus benchmark:

```powershell
python .\benchmark_corpus.py
```

If `pytest` is already installed globally, the install step is optional.
If the output directory already contains files, choose a new directory or pass
`-Force` to `reproduce.ps1`.

Direct scanner command:

```powershell
python .\crypto_pqc_radar.py `
  --root C:\path\to\repo `
  --out-dir .\reports\repo_crypto_radar `
  --repo-id repo-name
```

Use `--force` to write into a non-empty output directory. For CI, use
`--fail-on findings` or `--fail-on review` to return a non-zero exit code when
the scan should block a pipeline.

Optional suppressions file:

```powershell
python .\crypto_pqc_radar.py `
  --root C:\path\to\repo `
  --out-dir .\reports\repo_crypto_radar `
  --suppressions .\suppressions.json
```

Suppressions mark matching findings as suppressed but do not delete raw evidence.
Each suppression entry requires `reason`, `owner`, and `expires`.

The default pattern catalog is `pattern_catalog.json`. To test a custom catalog:

```powershell
python .\crypto_pqc_radar.py `
  --root C:\path\to\repo `
  --out-dir .\reports\repo_custom_catalog `
  --pattern-catalog .\pattern_catalog.json
```

Verifier command:

```powershell
python .\verify_crypto_radar.py `
  --root C:\path\to\repo `
  --report .\reports\repo_crypto_radar\qday_risk_report.json `
  --out .\reports\repo_crypto_radar\verifier_report.md
```

Batch scanner command:

```powershell
python .\batch_crypto_pqc_radar.py `
  --root C:\path\to\repo-a `
  --root C:\path\to\repo-b `
  --out-dir .\reports\batch_crypto_radar
```

Use `--roots-file .\roots.txt` for one repository root per line. Batch reports
count repeated passive static migration review signals across local repositories;
they do not prove shared vulnerability, runtime reachability, or an
organization-wide migration blocker.
When `--force` is used, batch output removal is allowed only for directories
previously marked as scanner output with `.crypto-pqc-radar-output`.

Evidence diff command:

```powershell
python .\diff_crypto_pqc_radar.py `
  --old .\reports\old\qday_risk_report.json `
  --new .\reports\new\qday_risk_report.json `
  --out .\reports\diff\evidence_diff.json
```

Diffs report static migration-review evidence deltas, not vulnerability
regressions.

Maintainer workflow templates:

- `templates\INTERNAL_AUDIT_TEMPLATE.md`: local triage before verifier approval.
- `templates\VERIFIED_MAINTAINER_NOTE_TEMPLATE.md`: use only after verifier approval.

## Outputs

- `crypto_inventory.csv`: one row per evidence item.
- `crypto_findings.csv`: deduplicated findings and verdicts.
- `crypto_review_paths.csv`: ranked passive review paths with score factors.
- `crypto_graph.dot`: repository-to-crypto evidence graph.
- `crypto_findings.sarif`: SARIF 2.1.0 passive findings export for code review tools.
- `crypto_cbom.json`: CBOM-style passive cryptographic inventory export.
- `qday_risk_report.json`: machine-readable report.
- `qday_risk_report.md`: human-readable report.
- `verifier_report.md` and `verifier_report.json`: second-pass evidence check.
- `downgrade_feedback.csv` and `downgrade_feedback.json`: verifier feedback rows for the evidence ledger loop.
- `internal_review_note.md`: non-sendable scanner note for local triage before verifier approval.
- `verified_maintainer_note.md`: short maintainer-facing note after verifier approval.
- `batch_summary.json`, `batch_summary.md`, `batch_repositories.csv`, and
  `batch_shared_crypto_signals.csv`: cross-repo passive evidence summaries.

## Verdict Classes

- `inventory_only`
- `migration_review`
- `hardcoded_crypto_material`
- `weak_or_legacy_algorithm`
- `pqc_absent_but_relevant`

## Development Loop

See `PROJECT_STEPS.md`. Each step should be implemented, reviewed by a second
agent, corrected, and then followed by the next step.

## Claim Boundary

Allowed claims:

- This repository contains code/config/dependencies matching crypto patterns.
- This is a passive static finding, not proof of exploitability.
- No PQC/hybrid migration signal was found by this scanner.
- The cited code path should be reviewed for migration planning.

Forbidden claims:

- The system can be hacked.
- RSA/ECDSA/secp256k1 was broken.
- Private keys can be recovered.
- A production system is vulnerable.
