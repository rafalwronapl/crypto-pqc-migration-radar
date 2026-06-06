# Claim Boundary

HDF-009 exists to find migration and review targets, not to break cryptography.

## Allowed

- Passive scan of public or authorized local repositories.
- Static inventory of RSA/ECDSA/secp256k1/Ed25519/JWT/TLS/PQC signals.
- Dependency graph analysis.
- Network ranking of migration bottlenecks.
- Maintainer-facing risk notes.
- Defensive remediation suggestions.
- Patch dry-runs only on local clones or owned forks.

## Not allowed

- Key recovery attempts.
- Signature forgery attempts.
- Decryption attempts.
- Brute force.
- Exploit generation.
- Active scanning of production endpoints.
- Testing leaked credentials or private keys.
- Claims that a live system is vulnerable without authorization.
- Instructions that help compromise a third-party system.

## Default phrasing

Use:

- "static finding"
- "migration risk"
- "review target"
- "legacy crypto dependency"
- "no visible PQC migration signal"
- "not proof of exploitability"

Avoid:

- "we can hack this"
- "broken crypto"
- "confirmed vulnerability in production"
- "private keys can be recovered"
- "attack path"

## Escalation path

If a scan finds a private key, token, password, or credential-like material:

1. Do not use it.
2. Do not test whether it works.
3. Record only the file path, line number, redacted prefix, and secret type.
4. Mark as `secret_exposure_review`.
5. Generate a responsible disclosure note.

