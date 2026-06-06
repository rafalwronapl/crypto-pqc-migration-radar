from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
WORKSTREAM = HERE.parents[1]
sys.path.insert(0, str(WORKSTREAM))
CORPUS = WORKSTREAM / "tests" / "fixtures" / "corpus"

from crypto_pqc_radar import CLAIM_BOUNDARY, build_review_paths, dedupe_findings, load_pattern_catalog, run, scan_repo, validate_pattern_catalog  # noqa: E402


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_scanner_detects_core_crypto_patterns(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "auth.ts").write_text(
        "import jwt from 'jsonwebtoken';\n"
        "export function signToken(payload: object, privateKey: string) {\n"
        "  return jwt.sign(payload, privateKey, { algorithm: 'RS256' });\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "tls.yaml").write_text("minVersion: TLSv1.0\nrejectUnauthorized: false\n", encoding="utf-8")
    (tmp_path / "wallet.go").write_text('curve := "secp256k1"\n_ = "privateKeyToAccount"\n', encoding="utf-8")
    (tmp_path / "authorized_keys").write_text("ssh-ed25519 AAAAredacted review-only\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("No post-quantum migration plan is documented yet.\n", encoding="utf-8")

    evidence = scan_repo(tmp_path)
    categories = {item.category for item in evidence}

    assert {"rsa", "jwt", "tls", "secp256k1", "ssh_key", "pqc_signal"}.issubset(categories)
    assert any(item.file_path == "src/auth.ts" and item.line == 3 and item.matched_text == "RS256" for item in evidence)


def test_findings_include_prompt_verdict_classes(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        "PUBLIC = '''-----BEGIN PUBLIC KEY-----\\nredacted\\n-----END PUBLIC KEY-----'''\n"
        "jwt_algorithm = 'HS256'\n",
        encoding="utf-8",
    )
    evidence = scan_repo(tmp_path)
    from crypto_pqc_radar import dedupe_findings

    findings = dedupe_findings(evidence)
    verdicts = {finding.verdict for finding in findings}

    assert "hardcoded_crypto_material" in verdicts
    assert "weak_or_legacy_algorithm" in verdicts
    assert "pqc_absent_but_relevant" in verdicts


def test_run_writes_verifier_friendly_outputs(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    (repo / "package.json").write_text('{"dependencies":{"jsonwebtoken":"9.0.0","jose":"5.0.0"}}', encoding="utf-8")
    (repo / "auth.js").write_text("jwt.verify(token, key, { algorithms: ['ES256'] })\n", encoding="utf-8")

    evidence, findings = run(repo, out)

    assert evidence
    assert findings
    for name in ("crypto_inventory.csv", "crypto_findings.csv", "crypto_review_paths.csv", "crypto_graph.dot", "crypto_findings.sarif", "qday_risk_report.json", "qday_risk_report.md", "internal_review_note.md"):
        assert (out / name).exists()
    assert (out / "crypto_cbom.json").exists()
    assert not (out / "maintainer_note.md").exists()
    assert (out / "evidence" / "evidence.jsonl").exists()

    inventory = rows(out / "crypto_inventory.csv")
    assert {"repo_id", "file_path", "line", "matched_text", "confidence"}.issubset(inventory[0])
    assert any(row["file_path"] == "auth.js" and row["line"] == "1" for row in inventory)

    report = json.loads((out / "qday_risk_report.json").read_text(encoding="utf-8"))
    assert report["claim_boundary"] == CLAIM_BOUNDARY
    assert report["pattern_catalog"]["version"] == "0.1.0"
    assert report["pattern_catalog"]["sha256"]
    assert report["evidence"][0]["snippet"]
    assert report["findings"][0]["evidence_grade"]
    assert report["findings"][0]["promotion_requirements"]
    assert report["findings"][0]["downgrade_reason"]
    report_md = (out / "qday_risk_report.md").read_text(encoding="utf-8")
    assert "not proof of exploitability" in report_md
    assert "--pattern-catalog" in report_md
    assert "Promotion:" in report_md
    internal_note = (out / "internal_review_note.md").read_text(encoding="utf-8")
    assert "not verifier-approved" in internal_note
    assert "do not send" in internal_note

    sarif = json.loads((out / "crypto_findings.sarif").read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "crypto-pqc-migration-radar"
    assert sarif["runs"][0]["results"]
    first_result = sarif["runs"][0]["results"][0]
    assert "not proof of exploitability" in first_result["message"]["text"]
    assert first_result["properties"]["evidence_grade"]
    assert first_result["properties"]["promotion_requirements"]

    cbom = json.loads((out / "crypto_cbom.json").read_text(encoding="utf-8"))
    assert cbom["bomFormat"] == "CryptoBOM"
    assert cbom["components"]
    assert "whatIsNotProven" in cbom["metadata"]


def test_run_accepts_stable_repo_id(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    (repo / "auth.js").write_text("jwt.sign({}, key, { algorithm: 'RS256' });\n", encoding="utf-8")

    evidence, findings = run(repo, out, repo_id="custom-repo")

    assert evidence
    assert findings
    assert {item.repo_id for item in evidence} == {"custom-repo"}
    assert {finding.repo_id for finding in findings} == {"custom-repo"}


def test_test_and_lockfile_contexts_are_downranked(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_keys.py").write_text("# RSA appears in a fixture comment\n", encoding="utf-8")
    (tmp_path / "Cargo.lock").write_text('[[package]]\nname = "rsa"\nversion = "0.9.0"\n', encoding="utf-8")

    evidence = scan_repo(tmp_path)

    assert any(item.context_kind == "test" and item.confidence < 0.7 for item in evidence)
    assert any(item.context_kind == "lockfile" and item.confidence < 0.7 for item in evidence)


def test_runtime_import_is_source_dependency_usage_not_vulnerability_claim(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "auth.ts").write_text(
        "import jwt from 'jsonwebtoken';\n"
        "export const token = jwt.sign(payload, key, { algorithm: 'RS256' });\n",
        encoding="utf-8",
    )

    evidence = scan_repo(tmp_path)
    findings = dedupe_findings(evidence)

    assert any(item.context_kind == "runtime" and item.source_kind == "import_dependency_usage" for item in evidence)
    assert any(finding.verdict == "migration_review" and finding.top_context_kind == "runtime" for finding in findings)
    assert not any("vulnerab" in finding.what_is_certified.lower() for finding in findings)


def test_language_aware_import_dependency_detection(tmp_path: Path) -> None:
    files = {
        "app.py": "from cryptography.hazmat.primitives.asymmetric import rsa\n",
        "app.js": "const jwt = require('jsonwebtoken');\n",
        "main.go": 'import "crypto/rsa"\n',
        "lib.rs": "use ed25519_dalek::Verifier; // Ed25519\n",
        "Auth.java": "import java.security.Signature;\n",
    }
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")

    evidence = scan_repo(tmp_path)
    import_paths = {item.file_path for item in evidence if item.source_kind == "import_dependency_usage"}

    assert {"app.py", "app.js", "main.go", "lib.rs", "Auth.java"}.issubset(import_paths)


def test_comment_mentions_are_not_import_dependency_usage(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("# import rsa in docs only\n", encoding="utf-8")

    evidence = scan_repo(tmp_path)

    assert any(item.source_kind == "comment" for item in evidence)
    assert not any(item.source_kind == "import_dependency_usage" for item in evidence)


def test_fake_key_in_test_fixture_is_inventory_only(tmp_path: Path) -> None:
    (tmp_path / "tests" / "fixtures").mkdir(parents=True)
    (tmp_path / "tests" / "fixtures" / "key.pem").write_text(
        "FAKE RSA TEST PRIVATE KEY MARKER\nredacted-fixture\nEND FAKE RSA TEST PRIVATE KEY MARKER\n",
        encoding="utf-8",
    )

    evidence = scan_repo(tmp_path)
    findings = dedupe_findings(evidence)

    assert any(item.context_kind == "fixture" for item in evidence)
    assert all(finding.verdict == "inventory_only" for finding in findings)
    assert any("non-runtime" in finding.what_is_certified for finding in findings)
    assert {finding.evidence_grade for finding in findings} == {"weak_context_inventory"}


def test_docs_example_with_rsa_jwt_is_inventory_only(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "jwt.md").write_text("Example: sign JWT with RSA and RS256 for documentation only.\n", encoding="utf-8")

    evidence = scan_repo(tmp_path)
    findings = dedupe_findings(evidence)

    assert {item.context_kind for item in evidence} == {"docs"}
    assert all(finding.verdict == "inventory_only" for finding in findings)


def test_lockfile_only_crypto_package_is_dependency_inventory(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text('{"packages":{"node_modules/rsa":{"name":"rsa","version":"1.0.0"}}}', encoding="utf-8")

    evidence = scan_repo(tmp_path)
    findings = dedupe_findings(evidence)

    assert any(item.context_kind == "lockfile" and item.source_kind == "dependency_inventory" for item in evidence)
    assert all(finding.verdict == "inventory_only" for finding in findings)


def test_generated_and_vendor_paths_are_downgraded(tmp_path: Path) -> None:
    (tmp_path / "generated").mkdir()
    (tmp_path / "vendor").mkdir()
    (tmp_path / "generated" / "auth.pb.go").write_text('const alg = "RS256"\n', encoding="utf-8")
    (tmp_path / "vendor" / "wallet.js").write_text("const curve = 'secp256k1';\n", encoding="utf-8")

    evidence = scan_repo(tmp_path)
    findings = dedupe_findings(evidence)

    assert {"generated", "vendor"}.issubset({item.context_kind for item in evidence})
    assert all(finding.verdict == "inventory_only" for finding in findings)


def test_runtime_hardcoded_crypto_material_remains_strong_signal(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "keys.py").write_text(
        "PUBLIC_KEY = '''-----BEGIN PUBLIC KEY-----\\nredacted\\n-----END PUBLIC KEY-----'''\n",
        encoding="utf-8",
    )

    evidence = scan_repo(tmp_path)
    findings = dedupe_findings(evidence)

    hardcoded = [finding for finding in findings if finding.verdict == "hardcoded_crypto_material"]
    assert hardcoded
    assert hardcoded[0].top_context_kind == "runtime"
    assert hardcoded[0].overall_score >= 70
    assert hardcoded[0].evidence_grade == "verifier_required"
    assert "Verifier must confirm" in hardcoded[0].promotion_requirements


def test_graph_edges_distinguish_imports_dependencies_and_lifecycle(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "auth.ts").write_text(
        "import jwt from 'jsonwebtoken';\n"
        "jwt.sign(payload, privateKey, { algorithm: 'RS256' });\n"
        "jwt.verify(token, publicKey, { algorithms: ['RS256'] });\n",
        encoding="utf-8",
    )
    (repo / "package.json").write_text('{"dependencies":{"jsonwebtoken":"9.0.0"}}', encoding="utf-8")

    run(repo, out)

    dot = (out / "crypto_graph.dot").read_text(encoding="utf-8")
    assert 'label="imports"' in dot
    assert 'label="depends_on"' in dot
    assert 'label="signs_with"' in dot
    assert 'label="verifies_with"' in dot


def test_review_paths_rank_runtime_lifecycle_above_lockfile_inventory(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "signer.py").write_text("sign(payload, privateKey, algorithm='RS256')\n", encoding="utf-8")
    (tmp_path / "Cargo.lock").write_text('[[package]]\nname = "rsa"\nversion = "0.9.0"\n', encoding="utf-8")

    evidence = scan_repo(tmp_path)
    findings = dedupe_findings(evidence)
    review_paths = build_review_paths(evidence, findings)

    assert review_paths[0]["file_path"] == "src/signer.py"
    assert "signs_with" in review_paths[0]["edge_kinds"]
    assert review_paths[0]["runtime_evidence_count"] > 0
    assert review_paths[0]["lifecycle_edge_count"] > 0
    lockfile = [path for path in review_paths if path["file_path"] == "Cargo.lock"][0]
    assert lockfile["downgrade_only"] is True
    assert lockfile["review_reason"] == "Inventory-only path unless runtime evidence is verified."


def test_json_and_markdown_include_review_paths(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    (repo / "auth.js").write_text("jwt.sign({}, privateKey, { algorithm: 'RS256' });\n", encoding="utf-8")

    run(repo, out)

    report = json.loads((out / "qday_risk_report.json").read_text(encoding="utf-8"))
    assert report["review_paths"]
    assert report["review_paths"][0]["claim_state"] == "local_signal"
    assert report["review_paths"][0]["edge_basis"] == "inferred_static_line_signal"
    assert report["review_paths"][0]["max_finding_score"] > 0
    review_path_rows = rows(out / "crypto_review_paths.csv")
    assert {"file_path", "rank_score", "edge_basis", "runtime_evidence_count", "downgrade_only"}.issubset(review_path_rows[0])
    report_md = (out / "qday_risk_report.md").read_text(encoding="utf-8")
    assert "Top Review Paths" in report_md
    assert "Claim Discipline" in report_md
    assert "inferred static review edges" in report_md


def test_review_paths_keep_all_verdicts_for_same_primitive_name(tmp_path: Path) -> None:
    catalog = tmp_path / "patterns.json"
    catalog.write_text(
        json.dumps(
            {
                "version": "collision-test",
                "patterns": [
                    {
                        "category": "hardcoded_rsa",
                        "primitive_or_protocol": "RSA",
                        "confidence": 0.95,
                        "note": "hardcoded test signal",
                        "tokens": ["-----BEGIN PUBLIC KEY-----"],
                    },
                    {
                        "category": "pqc_signal",
                        "primitive_or_protocol": "RSA",
                        "confidence": 0.95,
                        "note": "same primitive collision test",
                        "tokens": ["RSA_PQC_TEST_SIGNAL"],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "keys.py").write_text(
        "PUBLIC = '-----BEGIN PUBLIC KEY-----'\nRSA_PQC_TEST_SIGNAL = True\n",
        encoding="utf-8",
    )

    evidence = scan_repo(tmp_path, pattern_catalog=catalog)
    findings = dedupe_findings(evidence)
    review_paths = build_review_paths(evidence, findings)

    assert {"hardcoded_crypto_material", "inventory_only"}.issubset(set(review_paths[0]["verdicts"]))


def test_docs_with_many_hits_do_not_outrank_runtime_lifecycle_path(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "docs" / "crypto.md").write_text(("RSA RS256 JWT ECDSA secp256k1\n" * 5), encoding="utf-8")
    (tmp_path / "src" / "signer.py").write_text("sign(payload, privateKey, algorithm='RS256')\n", encoding="utf-8")

    evidence = scan_repo(tmp_path)
    findings = dedupe_findings(evidence)
    review_paths = build_review_paths(evidence, findings)

    assert review_paths[0]["file_path"] == "src/signer.py"
    assert review_paths[0]["rank_score"] > [path for path in review_paths if path["file_path"] == "docs/crypto.md"][0]["rank_score"]


def test_custom_pattern_catalog_is_used(tmp_path: Path) -> None:
    catalog = tmp_path / "patterns.json"
    catalog.write_text(
        json.dumps(
            {
                "version": "test",
                "patterns": [
                    {
                        "category": "custom_crypto",
                        "primitive_or_protocol": "CUSTOM",
                        "confidence": 0.91,
                        "note": "custom test signal",
                        "tokens": ["CustomCryptoThing"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text("CustomCryptoThing()\nRSA\n", encoding="utf-8")

    evidence = scan_repo(tmp_path, pattern_catalog=catalog)

    assert {item.category for item in evidence} == {"custom_crypto"}
    assert evidence[0].matched_text == "CustomCryptoThing"


def test_pattern_catalog_validation_rejects_bad_entries() -> None:
    bad_catalog = {
        "version": "bad",
        "patterns": [
            {
                "category": "rsa",
                "primitive_or_protocol": "RSA",
                "confidence": 1.5,
                "note": "bad",
                "tokens": ["RSA"],
            }
        ],
    }

    try:
        validate_pattern_catalog(bad_catalog)
    except ValueError as exc:
        assert "confidence" in str(exc)
    else:
        raise AssertionError("invalid catalog was accepted")


def test_pattern_catalog_validation_requires_version() -> None:
    try:
        validate_pattern_catalog({"patterns": [{"category": "x", "primitive_or_protocol": "X", "confidence": 0.5, "note": "x", "tokens": ["X"]}]})
    except ValueError as exc:
        assert "version" in str(exc)
    else:
        raise AssertionError("unversioned catalog was accepted")


def test_pattern_catalog_validation_rejects_boolean_confidence() -> None:
    try:
        validate_pattern_catalog(
            {
                "version": "bad",
                "patterns": [
                    {
                        "category": "x",
                        "primitive_or_protocol": "X",
                        "confidence": True,
                        "note": "x",
                        "tokens": ["X"],
                    }
                ],
            }
        )
    except ValueError as exc:
        assert "confidence" in str(exc)
    else:
        raise AssertionError("boolean confidence was accepted")


def test_default_pattern_catalog_loads() -> None:
    patterns = load_pattern_catalog()

    assert any(pattern.category == "rsa" and pattern.token == "RS256" for pattern in patterns)


def test_baseline_corpus_expected_contexts_verdicts_and_grades() -> None:
    expected = json.loads((CORPUS / "expected_corpus.json").read_text(encoding="utf-8"))

    for fixture_name, requirements in expected.items():
        fixture_root = CORPUS / fixture_name
        evidence = scan_repo(fixture_root)
        findings = dedupe_findings(evidence)
        contexts = {item.context_kind for item in evidence}
        verdicts = {finding.verdict for finding in findings}
        grades = {finding.evidence_grade for finding in findings}

        assert set(requirements["required_contexts"]).issubset(contexts), fixture_name
        assert set(requirements["required_verdicts"]).issubset(verdicts), fixture_name
        assert set(requirements["required_evidence_grades"]).issubset(grades), fixture_name


def test_self_scan_tooling_catalog_and_fixtures_are_not_app_runtime() -> None:
    evidence = scan_repo(WORKSTREAM)
    by_path = {item.file_path: item.context_kind for item in evidence}

    assert by_path["pattern_catalog.json"] == "catalog"
    assert by_path["crypto_pqc_radar.py"] == "tooling"
    assert any(item.context_kind == "fixture" for item in evidence if item.file_path.startswith("tests/fixtures/"))

    findings = dedupe_findings(evidence)
    review_paths = build_review_paths(evidence, findings)
    pattern_catalog_paths = [path for path in review_paths if path["file_path"] == "pattern_catalog.json"]
    tool_paths = [path for path in review_paths if path["file_path"] == "crypto_pqc_radar.py"]

    assert pattern_catalog_paths and pattern_catalog_paths[0]["downgrade_only"] is True
    assert tool_paths and tool_paths[0]["downgrade_only"] is True


def test_self_scan_mini_repo_ranks_real_runtime_above_catalog_and_tooling(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "pattern_catalog.json").write_text('{"tokens":["RSA","JWT","TLS","RS256"]}\n', encoding="utf-8")
    (tmp_path / "crypto_pqc_radar.py").write_text("RSA JWT TLS RS256 scanner wording\n", encoding="utf-8")
    (tmp_path / "src" / "auth.js").write_text("jwt.sign(payload, privateKey, { algorithm: 'RS256' });\n", encoding="utf-8")

    evidence = scan_repo(tmp_path)
    findings = dedupe_findings(evidence)
    review_paths = build_review_paths(evidence, findings)

    contexts_by_path = {item.file_path: item.context_kind for item in evidence}
    assert contexts_by_path["pattern_catalog.json"] == "catalog"
    assert contexts_by_path["crypto_pqc_radar.py"] == "tooling"
    assert review_paths[0]["file_path"] == "src/auth.js"
    assert [path for path in review_paths if path["file_path"] == "pattern_catalog.json"][0]["downgrade_only"] is True
    assert [path for path in review_paths if path["file_path"] == "crypto_pqc_radar.py"][0]["downgrade_only"] is True


def test_baseline_corpus_sarif_shape(tmp_path: Path) -> None:
    out = tmp_path / "out"
    run(CORPUS / "runtime_app", out)

    sarif = json.loads((out / "crypto_findings.sarif").read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"]
    result = sarif["runs"][0]["results"][0]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert result["properties"]["claim_state"] == "local_signal"


def test_suppressions_mark_findings_without_deleting_raw_evidence(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    suppressions = tmp_path / "suppressions.json"
    repo.mkdir()
    (repo / "auth.js").write_text("jwt.sign({}, privateKey, { algorithm: 'RS256' });\n", encoding="utf-8")
    suppressions.write_text(
        json.dumps(
            {
                "suppressions": [
                    {
                        "match": {"verdict": "migration_review", "path_prefix": "auth.js"},
                        "reason": "Known synthetic migration fixture.",
                        "owner": "security-review",
                        "expires": "2026-12-31",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    evidence, findings = run(repo, out, suppressions=suppressions)

    assert evidence
    suppressed = [finding for finding in findings if finding.suppression_status == "suppressed"]
    assert suppressed
    assert suppressed[0].suppression_reason == "Known synthetic migration fixture."
    report = json.loads((out / "qday_risk_report.json").read_text(encoding="utf-8"))
    assert report["summary"]["suppression_counts"]["suppressed"] >= 1
    assert report["evidence"]
    internal_note = (out / "internal_review_note.md").read_text(encoding="utf-8")
    assert "Known synthetic migration fixture" not in internal_note


def test_suppression_file_requires_owner_reason_and_expiry(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    suppressions = tmp_path / "bad_suppressions.json"
    repo.mkdir()
    (repo / "auth.js").write_text("jwt.sign({}, key, { algorithm: 'RS256' });\n", encoding="utf-8")
    suppressions.write_text(json.dumps({"suppressions": [{"match": {"verdict": "migration_review"}, "reason": "x"}]}), encoding="utf-8")

    try:
        run(repo, out, suppressions=suppressions)
    except ValueError as exc:
        assert "owner" in str(exc) or "expires" in str(exc)
    else:
        raise AssertionError("invalid suppression file was accepted")
