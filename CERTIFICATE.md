# Certificate Package

## Artifact ID

`crypto-pqc-migration-radar-0.1.0-local`

## Verifier

- `quality_gate.py`
- `verify_crypto_radar.py`
- `reproduce.ps1`
- `tests/`

## Claim State

`finite_certificate`

The certificate covers the local implementation and synthetic regression corpus.
It does not claim real-world exploitability or completeness over arbitrary
repositories.

## What Is Certified

- The scanner emits passive static evidence rows for configured crypto/PQC
  patterns.
- The scanner classifies context and records evidence grades, downgrade reasons,
  and promotion requirements.
- The verifier emits line-check results, verifier-approved maintainer notes, and
  downgrade feedback rows.
- Batch reports aggregate repeated static migration review signals across local
  repositories.
- SARIF and evidence diff outputs preserve defensive wording.
- The baseline corpus expected contexts, verdicts, evidence grades, SARIF shape,
  and batch shape pass tests.
- The labeled synthetic corpus benchmark reports precision/recall for the
  bounded fixture task.
- Self-scan catalog/tooling/fixture evidence is preserved as raw evidence but
  downgraded from application runtime claims.

## What Is Not Certified

- Exploitability.
- Runtime reachability.
- Key validity.
- Production vulnerability.
- Complete cryptographic inventory for every language/framework.
- Real-world precision/recall outside the labeled synthetic corpus.
- Organization-wide migration blockers.

## Nearest Baseline

Passive static pattern inventory with context downgrade and verifier-gated
maintainer workflow.

## Feedback If Downgraded

Keep downgraded rows as inventory evidence. Promote only after verifier-approved
line evidence, runtime-classified source context, ownership review, and migration
relevance are confirmed.

## Reproduction

```powershell
cd crypto-pqc-migration-radar
python .\quality_gate.py
.\reproduce.ps1 -Force
```
