# Defensive Use

This workstream is designed for useful security work without crossing into
unauthorized attack behavior.

## What it can discover

- Repositories that depend on legacy public-key crypto.
- JWT/TLS configurations that deserve review.
- Long-lived signing or identity code paths with no visible migration plan.
- Crypto dependencies that are central in the dependency graph.
- Projects where PQC readiness is absent from docs, dependencies, and config.

## What it cannot prove

- It cannot prove a system is hackable.
- It cannot prove a private key can be recovered.
- It cannot prove a service is deployed with the scanned configuration.
- It cannot prove exploitability from a static match alone.

## Safe maintainer note style

Use this shape:

```text
Hi,

I passively reviewed the public repository <repo> for crypto migration signals.
This was a static repository review only; I did not test live systems or attempt
to exploit anything.

The main review target is <finding>, with evidence in <file:line>. I did not
find a visible PQC/hybrid migration signal for this path.

This is not proof of exploitability. It is a defensive migration-readiness note.
If useful, I can share the generated inventory/report or prepare a small PR.
```

## Practical product angle

The useful artifact is not "we broke crypto." The useful artifact is:

> Upload or clone a repo, get a migration-risk map, evidence lines, a ranked
> review queue, and a maintainer-safe report.

