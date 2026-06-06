# MVP Plan

Goal: deliver a working artifact that turns a repository into a crypto migration
review package.

## MVP command shape

Planned command:

```powershell
python .\crypto_pqc_radar.py `
  --root C:\path\to\repo `
  --out-dir .\reports\repo_crypto_radar
```

Planned verifier command:

```powershell
python .\verify_crypto_radar.py `
  --root C:\path\to\repo `
  --report .\reports\repo_crypto_radar\qday_risk_report.json `
  --out .\reports\repo_crypto_radar\verifier_report.md
```

No active network access is required for MVP.

## MVP score

Suggested scoring:

- `primitive_weight`: RSA/ECDSA/secp256k1/JWT/TLS/PQC signal.
- `runtime_weight`: source/config > lockfile > docs/test.
- `long_lived_key_weight`: signing, identity, wallet, cert, firmware, package
  signing.
- `centrality_weight`: number of source/config/dependency paths connected to the
  primitive or library.
- `migration_gap_weight`: no visible PQC/hybrid plan where long-lived public-key
  crypto exists.
- `confidence_penalty`: comments, generated files, examples, vendored code.

The score should rank review priority. It must not be presented as probability
of exploit.

## Low-hanging fruit

First practical wins:

- JWT algorithms and key handling.
- `rejectUnauthorized: false`, `CERT_NONE`, `InsecureSkipVerify`.
- RSA/ECDSA/secp256k1 use on signing paths.
- Crypto libraries with old dependency versions from HDF-008.
- No `SECURITY.md` or migration note in projects centered on signing/auth.

## Future extensions

- GitHub passive scanner for public repos.
- Cross-repo graph: which libraries appear as common migration bottlenecks.
- Patch readiness advisor for crypto libraries.
- PQC dependency inventory.
- Maintainer note generator with verifier gate.
- Integration with HDF-008 supply-chain graph.

