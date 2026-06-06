# Reproduce

Run from this directory:

```powershell
python -m pip install -e ".[test]"
python .\quality_gate.py
.\reproduce.ps1 -Force
```

Default outputs are written under:

```text
reports\local_crypto_radar
```

For a fresh output directory:

```powershell
.\reproduce.ps1 -OutDir .\reports\fresh_run -Force
```

Expected result:

- pytest passes;
- quality gate passes;
- scanner writes inventory, findings, review paths, SARIF, Markdown, and JSON;
- verifier writes verifier report, downgrade feedback, and verifier-approved
  maintainer note;
- batch scanner writes cross-repository summary outputs.

Safety boundary:

The reproduction does not contact live services, test credentials, recover keys,
forge signatures, decrypt data, or claim exploitability.
