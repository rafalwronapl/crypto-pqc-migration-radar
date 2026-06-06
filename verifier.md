# Verifier

The verifier is the second-agent layer for HDF-009. Its job is to downgrade
overclaims and allow only evidence-backed defensive findings.

## Inputs

- `crypto_inventory.csv`
- `crypto_findings.csv`
- `qday_risk_report.json`
- Repository path

## Required checks

For each high or urgent finding:

1. Confirm the file exists and the line contains the claimed evidence.
2. Classify the file context: runtime source, config, test, docs, generated,
   lockfile, or vendored code.
3. Check whether the match is code, comment, example, or dependency metadata.
4. Check whether the primitive/protocol is actually used or only mentioned.
5. Check whether there is a visible PQC/hybrid migration signal in nearby docs,
   config, dependencies, or security notes.
6. Confirm the finding does not rely on contacting a live system.
7. Confirm the maintainer-facing text does not claim exploitability.

## Downgrade rules

Downgrade to `inventory_only` when:

- Evidence is docs-only.
- Evidence is tests-only.
- Evidence is generated or vendored code.
- Evidence is lockfile-only and no runtime source/config path mentions it.
- Evidence is a generic word such as `crypto` without primitive/protocol context.

Downgrade `urgent_review` to `legacy_crypto_dependency` when:

- The primitive appears in runtime code but not on auth/signing/key lifecycle
  paths.
- The scanner cannot identify whether keys are long-lived.
- The scanner cannot distinguish public-key signing from local test utilities.

Reject maintainer claim when:

- The report says or implies the app can be hacked.
- The report says a private key can be recovered.
- The report says a production service is vulnerable.
- The report includes exploit steps.
- The report uses secrets found in the repo for validation.

## Pass criteria

A finding can be sent to a maintainer when:

- It has at least one line-level evidence item.
- The verifier confirms the context.
- The claim boundary is included.
- The recommended next step is review, migration planning, config cleanup, or a
  defensive patch.

## Reviewer verdicts

- `verified_static_finding`
- `verified_inventory_only`
- `downgraded_context_weak`
- `rejected_overclaim`
- `blocked_missing_evidence`

## Example safe verdict

> Verified static finding: repository uses `jsonwebtoken` with `RS256` in
> runtime auth code. This does not prove exploitability. It supports a
> maintainer-facing recommendation to review long-lived JWT signing keys and
> document a PQC/hybrid migration path.

