from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


SCANNER_VERSION = "0.1.0"
DEFAULT_PATTERN_CATALOG = Path(__file__).with_name("pattern_catalog.json")
CLAIM_BOUNDARY = (
    "This is a passive static review of repository contents. It is not proof of "
    "exploitability and does not claim that any production system is vulnerable."
)

INVENTORY_COLUMNS = [
    "repo_id",
    "file_path",
    "line",
    "category",
    "primitive_or_protocol",
    "matched_text",
    "context_kind",
    "confidence",
    "runtime_hint",
    "source_kind",
    "notes",
]

FINDING_COLUMNS = [
    "finding_id",
    "repo_id",
    "verdict",
    "title",
    "primitive_or_protocol",
    "impact_area",
    "runtime_confidence",
    "long_lived_key_score",
    "dependency_centrality",
    "migration_gap_score",
    "overall_score",
    "evidence_count",
    "top_evidence_path",
    "top_evidence_line",
    "top_context_kind",
    "verifier_status",
    "claim_allowed",
    "claim_state",
    "evidence_grade",
    "downgrade_reason",
    "promotion_requirements",
    "suppression_status",
    "suppression_reason",
    "suppression_owner",
    "suppression_expires",
    "what_is_certified",
    "what_is_not_certified",
    "nearest_baseline",
    "feedback_if_downgraded",
    "recommended_next_step",
]

REVIEW_PATH_COLUMNS = [
    "file_path",
    "rank_score",
    "contexts",
    "edge_kinds",
    "edge_basis",
    "primitive_or_protocols",
    "verdicts",
    "evidence_count",
    "runtime_evidence_count",
    "dependency_edge_count",
    "lifecycle_edge_count",
    "primitive_count",
    "category_count",
    "max_finding_score",
    "downgrade_only",
    "claim_state",
    "review_reason",
]

INCLUDED_SUFFIXES = {
    ".js",
    ".ts",
    ".tsx",
    ".py",
    ".go",
    ".rs",
    ".java",
    ".kt",
    ".cs",
    ".rb",
    ".php",
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
    ".swift",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".conf",
    ".cnf",
    ".md",
    ".xml",
    ".lock",
    ".pub",
    ".pem",
    ".key",
    ".gemspec",
    ".gradle",
}

INCLUDED_NAMES = {
    ".env.example",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "package.json",
    "package-lock.json",
    "pyproject.toml",
    "requirements.txt",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "pom.xml",
    "build.gradle",
    "composer.json",
    "composer.lock",
    "Gemfile",
    "Gemfile.lock",
    "nginx.conf",
    "traefik.yml",
    "caddyfile",
    "README.md",
    "SECURITY.md",
    "authorized_keys",
    "known_hosts",
}

EXCLUDED_PARTS = {
    ".git",
    "node_modules",
    "dist",
    "build",
    "target",
    "reports",
    "__pycache__",
    ".pytest_cache",
}

RISK_TERMS = re.compile(
    r"\b(sign|verify|token|auth|session|wallet|address|certificate|x509|csr|keystore|privateKey|"
    r"publicKey|issuer|jwks|firmware|package signing|release signing|saml|ssh ca)\b",
    re.IGNORECASE,
)

COMMENT_MARKERS = ("#", "//", "/*", "*", "<!--")
RUNTIME_CONTEXTS = {"runtime"}
WEAK_CONTEXTS = {"test", "fixture", "docs", "example", "generated", "vendor", "tooling", "catalog", "lockfile", "unknown"}
DEPENDENCY_CONTEXTS = {"manifest", "lockfile"}
CATALOG_NAMES = {"pattern_catalog.json", "patterns.json"}
TOOLING_NAMES = {
    "crypto_pqc_radar.py",
    "verify_crypto_radar.py",
    "batch_crypto_pqc_radar.py",
    "diff_crypto_pqc_radar.py",
    "quality_gate.py",
    "reproduce.ps1",
}
MANIFEST_NAMES = {
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "go.mod",
    "Cargo.toml",
    "pom.xml",
    "build.gradle",
    "composer.json",
    "Gemfile",
}
LOCKFILE_NAMES = {"package-lock.json", "go.sum", "Cargo.lock", "Gemfile.lock", "composer.lock"}
IMPORT_DEPENDENCY_RE = re.compile(
    r"\b(import|from|require|using|use|extern crate|include|package)\b|^\s*#include\s*[<\"]",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Pattern:
    category: str
    primitive_or_protocol: str
    token: str
    confidence: float
    note: str

    @property
    def regex(self) -> re.Pattern[str]:
        escaped = re.escape(self.token)
        if re.match(r"^[A-Za-z0-9_@./+-]+$", self.token):
            return re.compile(rf"(?<![A-Za-z0-9_@./+-]){escaped}(?![A-Za-z0-9_@./+-])", re.IGNORECASE)
        return re.compile(escaped, re.IGNORECASE)


@dataclass
class Evidence:
    repo_id: str
    file_path: str
    line: int
    category: str
    primitive_or_protocol: str
    matched_text: str
    context_kind: str
    confidence: float
    runtime_hint: str
    source_kind: str
    notes: str
    snippet: str


@dataclass
class Finding:
    finding_id: str
    repo_id: str
    verdict: str
    title: str
    primitive_or_protocol: str
    impact_area: str
    runtime_confidence: float
    long_lived_key_score: float
    dependency_centrality: int
    migration_gap_score: float
    overall_score: float
    evidence_count: int
    top_evidence_path: str
    top_evidence_line: int
    top_context_kind: str
    verifier_status: str
    claim_allowed: str
    claim_state: str
    evidence_grade: str
    downgrade_reason: str
    promotion_requirements: str
    suppression_status: str
    suppression_reason: str
    suppression_owner: str
    suppression_expires: str
    what_is_certified: str
    what_is_not_certified: str
    nearest_baseline: str
    feedback_if_downgraded: str
    recommended_next_step: str


def validate_pattern_catalog(data: object) -> list[Pattern]:
    if not isinstance(data, dict):
        raise ValueError("pattern catalog must be a JSON object")
    version = data.get("version")
    if not isinstance(version, str) or not version.strip():
        raise ValueError("pattern catalog must contain a non-empty string 'version'")
    raw_patterns = data.get("patterns")
    if not isinstance(raw_patterns, list) or not raw_patterns:
        raise ValueError("pattern catalog must contain a non-empty 'patterns' list")

    patterns: list[Pattern] = []
    seen_tokens: set[tuple[str, str]] = set()
    for index, entry in enumerate(raw_patterns, start=1):
        if not isinstance(entry, dict):
            raise ValueError(f"pattern entry {index} must be an object")
        category = require_string(entry, "category", index)
        primitive = require_string(entry, "primitive_or_protocol", index)
        note = require_string(entry, "note", index)
        confidence = entry.get("confidence")
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 < float(confidence) <= 1:
            raise ValueError(f"pattern entry {index} confidence must be a number in (0, 1]")
        tokens = entry.get("tokens")
        if not isinstance(tokens, list) or not tokens:
            raise ValueError(f"pattern entry {index} tokens must be a non-empty list")
        for token in tokens:
            if not isinstance(token, str) or not token.strip():
                raise ValueError(f"pattern entry {index} contains an empty or non-string token")
            key = (category, token.lower())
            if key in seen_tokens:
                raise ValueError(f"duplicate token in category {category}: {token}")
            seen_tokens.add(key)
            patterns.append(Pattern(category, primitive, token, float(confidence), note))
    return patterns


def require_string(entry: dict[str, object], key: str, index: int) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"pattern entry {index} requires non-empty string field '{key}'")
    return value


def load_pattern_catalog(path: Path = DEFAULT_PATTERN_CATALOG) -> list[Pattern]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"could not read pattern catalog {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in pattern catalog {path}: {exc}") from exc
    return validate_pattern_catalog(data)


def pattern_catalog_version(path: Path) -> str:
    data = json.loads(path.read_text(encoding="utf-8"))
    version = data.get("version")
    if not isinstance(version, str) or not version.strip():
        raise ValueError("pattern catalog must contain a non-empty string 'version'")
    return version


def repo_id_for(root: Path) -> str:
    resolved = str(root.resolve())
    digest = hashlib.sha1(resolved.encode("utf-8")).hexdigest()[:10]
    return f"{root.name}-{digest}"


def should_scan(path: Path, root: Path) -> bool:
    rel = path.relative_to(root)
    if path.is_symlink():
        return False
    if any(part in EXCLUDED_PARTS for part in rel.parts):
        return False
    if path.name.endswith(".min.js"):
        return False
    return path.name in INCLUDED_NAMES or path.name.lower() == "caddyfile" or path.suffix in INCLUDED_SUFFIXES


def context_kind(path: Path, root: Path) -> str:
    rel_parts = {part.lower() for part in path.relative_to(root).parts}
    name = path.name
    lower_name = name.lower()
    suffix = path.suffix.lower()
    if lower_name in CATALOG_NAMES or lower_name.endswith(("_catalog.json", "-catalog.json")):
        return "catalog"
    if lower_name in TOOLING_NAMES or any(part in rel_parts for part in ("tools", "scripts", ".github", "workflows")):
        return "tooling"
    if any(part in rel_parts for part in ("fixtures", "__fixtures__", "fixture", "corpus")):
        return "fixture"
    if any(part in rel_parts for part in ("vendor", "third_party", "third-party", "external")):
        return "vendor"
    if any(part in rel_parts for part in ("generated", "gen", "dist", "build")) or lower_name.endswith((".pb.go", ".min.js")):
        return "generated"
    if any(part in rel_parts for part in ("example", "examples", "sample", "samples", "demo", "demos")):
        return "example"
    if suffix == ".md" or any(part in rel_parts for part in ("docs", "doc", "documentation")):
        return "docs"
    if any(part in rel_parts for part in ("test", "tests", "__tests__")) or re.search(r"(^|[_.-])test([_.-]|$)", lower_name):
        return "test"
    if name in LOCKFILE_NAMES:
        return "lockfile"
    if name in MANIFEST_NAMES:
        return "manifest"
    if suffix in INCLUDED_SUFFIXES or name in INCLUDED_NAMES or lower_name == "caddyfile":
        return "runtime"
    return "unknown"


def source_kind_for(line: str, ctx: str, category: str, path: Path | None = None) -> str:
    stripped = line.strip()
    if not stripped:
        return "blank"
    if stripped.startswith(COMMENT_MARKERS):
        return "comment"
    if ctx in DEPENDENCY_CONTEXTS:
        return "dependency_inventory"
    if ctx == "runtime" and (category == "crypto_library" or is_import_dependency_line(line, path)):
        return "import_dependency_usage"
    return "code_or_config"


def is_import_dependency_line(line: str, path: Path | None = None) -> bool:
    stripped = line.strip()
    suffix = path.suffix.lower() if path else ""
    name = path.name if path else ""
    if suffix == ".py":
        return bool(re.match(r"^(import\s+[\w.]+|from\s+[\w.]+\s+import\s+)", stripped))
    if suffix in {".js", ".ts", ".tsx"}:
        return bool(re.match(r"^(import\s+.+\s+from\s+['\"]|import\s+['\"]|const\s+\w+\s*=\s*require\(['\"]|let\s+\w+\s*=\s*require\(['\"]|var\s+\w+\s*=\s*require\(['\"])", stripped))
    if suffix == ".go":
        return bool(re.match(r"^(import\s+(\(|[\"]|`))", stripped))
    if suffix == ".rs":
        return bool(re.match(r"^(use\s+[\w:]+|extern\s+crate\s+\w+)", stripped))
    if suffix in {".java", ".kt"}:
        return bool(re.match(r"^import\s+[\w.*]+;", stripped))
    if suffix in {".c", ".cc", ".cpp", ".h", ".hpp"}:
        return stripped.startswith("#include")
    if name in MANIFEST_NAMES or name in LOCKFILE_NAMES:
        return True
    return bool(IMPORT_DEPENDENCY_RE.search(line))


def runtime_hint_for(line: str, ctx: str) -> str:
    if ctx == "runtime":
        if RISK_TERMS.search(line):
            return "runtime_or_key_lifecycle_hint"
        return "possible_runtime"
    if ctx in DEPENDENCY_CONTEXTS:
        return "dependency_inventory"
    return "weak_context"


def adjusted_confidence(pattern: Pattern, line: str, ctx: str, source_kind: str) -> float:
    confidence = pattern.confidence
    if RISK_TERMS.search(line):
        confidence += 0.1
    if ctx in {"docs", "test", "fixture", "example", "generated", "vendor", "tooling", "catalog", "unknown"}:
        confidence -= 0.25
    if ctx == "lockfile":
        confidence -= 0.2
    if ctx == "manifest":
        confidence -= 0.1
    if source_kind == "comment":
        confidence -= 0.15
    if source_kind == "import_dependency_usage":
        confidence -= 0.05
    return round(max(0.1, min(confidence, 0.99)), 2)


def scan_repo(root: Path, repo_id: str | None = None, pattern_catalog: Path = DEFAULT_PATTERN_CATALOG) -> list[Evidence]:
    root = root.resolve()
    repo_id = repo_id or repo_id_for(root)
    compiled = [(pattern, pattern.regex) for pattern in load_pattern_catalog(pattern_catalog)]
    evidence: list[Evidence] = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        if not should_scan(path, root):
            continue
        ctx = context_kind(path, root)
        rel = path.relative_to(root).as_posix()
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for line_no, line in enumerate(lines, start=1):
            for pattern, regex in compiled:
                for match in regex.finditer(line):
                    source_kind = source_kind_for(line, ctx, pattern.category, path)
                    evidence.append(
                        Evidence(
                            repo_id=repo_id,
                            file_path=rel,
                            line=line_no,
                            category=pattern.category,
                            primitive_or_protocol=pattern.primitive_or_protocol,
                            matched_text=match.group(0),
                            context_kind=ctx,
                            confidence=adjusted_confidence(pattern, line, ctx, source_kind),
                            runtime_hint=runtime_hint_for(line, ctx),
                            source_kind=source_kind,
                            notes=pattern.note,
                            snippet=line.strip()[:240],
                        )
                    )
    return evidence


def dedupe_findings(evidence: list[Evidence]) -> list[Finding]:
    by_key: dict[tuple[str, str], list[Evidence]] = {}
    for item in evidence:
        by_key.setdefault((item.category, item.primitive_or_protocol), []).append(item)

    has_pqc = any(item.category == "pqc_signal" for item in evidence)
    findings: list[Finding] = []
    for index, ((category, primitive), items) in enumerate(sorted(by_key.items()), start=1):
        runtime_items = [item for item in items if item.context_kind in RUNTIME_CONTEXTS]
        lifecycle_items = [item for item in runtime_items if RISK_TERMS.search(item.snippet)]
        hardcoded_runtime_items = [item for item in runtime_items if item.matched_text.startswith("-----BEGIN")]
        top_pool = hardcoded_runtime_items or runtime_items or items
        top = sorted(top_pool, key=lambda item: (context_rank(item.context_kind), item.confidence, -item.line), reverse=True)[0]
        runtime_confidence = round(max((item.confidence for item in runtime_items), default=max(item.confidence for item in items) * 0.5), 2)
        long_lived_score = round(min(1.0, (len(lifecycle_items) + len(hardcoded_runtime_items)) / 3), 2)
        centrality = len({item.file_path for item in items})
        migration_gap = 0.0 if has_pqc or category == "pqc_signal" else (0.7 if lifecycle_items else 0.35)
        if not runtime_items:
            migration_gap *= 0.4
        score = round((runtime_confidence * 40) + (long_lived_score * 25) + min(centrality, 8) * 3 + (migration_gap * 25), 2)
        if hardcoded_runtime_items:
            score = round(min(100.0, score + 25), 2)
        verdict = classify_verdict(category, primitive, items, lifecycle_items, has_pqc)
        finding_id = f"CRYPTO-{index:03d}-{hashlib.sha1((category + primitive).encode('utf-8')).hexdigest()[:6]}"
        claim_details = claim_details_for(verdict, items, runtime_items)
        ledger_details = evidence_ledger_for(verdict, items, runtime_items, lifecycle_items)
        findings.append(
            Finding(
                finding_id=finding_id,
                repo_id=top.repo_id,
                verdict=verdict,
                title=title_for(verdict, primitive),
                primitive_or_protocol=primitive,
                impact_area=impact_area_for(items),
                runtime_confidence=runtime_confidence,
                long_lived_key_score=long_lived_score,
                dependency_centrality=centrality,
                migration_gap_score=round(migration_gap, 2),
                overall_score=score,
                evidence_count=len(items),
                top_evidence_path=top.file_path,
                top_evidence_line=top.line,
                top_context_kind=top.context_kind,
                verifier_status="not_verified_static_mvp",
                claim_allowed="yes_static_only",
                claim_state=claim_details["claim_state"],
                evidence_grade=ledger_details["evidence_grade"],
                downgrade_reason=ledger_details["downgrade_reason"],
                promotion_requirements=ledger_details["promotion_requirements"],
                suppression_status="active",
                suppression_reason="",
                suppression_owner="",
                suppression_expires="",
                what_is_certified=claim_details["what_is_certified"],
                what_is_not_certified=claim_details["what_is_not_certified"],
                nearest_baseline=claim_details["nearest_baseline"],
                feedback_if_downgraded=claim_details["feedback_if_downgraded"],
                recommended_next_step=recommendation_for(verdict),
            )
        )

    relevant_public_key = any(f.verdict in {"migration_review", "weak_or_legacy_algorithm"} for f in findings)
    if relevant_public_key and not has_pqc:
        first = sorted(evidence, key=lambda item: item.confidence, reverse=True)[0]
        findings.append(
            Finding(
                finding_id="CRYPTO-PQC-GAP",
                repo_id=first.repo_id,
                verdict="pqc_absent_but_relevant",
                title="No visible PQC or hybrid migration signal found",
                primitive_or_protocol="PQC/hybrid",
                impact_area="migration_planning",
                runtime_confidence=0.6,
                long_lived_key_score=0.0,
                dependency_centrality=0,
                migration_gap_score=0.85,
                overall_score=45.25,
                evidence_count=0,
                top_evidence_path="",
                top_evidence_line=0,
                top_context_kind="unknown",
                verifier_status="not_verified_static_mvp",
                claim_allowed="yes_static_only",
                claim_state="local_signal",
                evidence_grade="migration_gap_signal",
                downgrade_reason="No direct line evidence by design; this is an absence-of-local-PQC-token signal tied to other static crypto evidence.",
                promotion_requirements="Verify runtime ownership and expected cryptographic lifetime before treating this as a migration planning item.",
                suppression_status="active",
                suppression_reason="",
                suppression_owner="",
                suppression_expires="",
                what_is_certified="Scanner found relevant static crypto evidence and no local text matching PQC/hybrid migration tokens.",
                what_is_not_certified="This does not prove the repository lacks a migration plan or that any system is vulnerable.",
                nearest_baseline="Passive local pattern inventory; no live endpoint or exploitability baseline.",
                feedback_if_downgraded="Keep as migration-planning signal unless runtime ownership and lifecycle evidence are verified.",
                recommended_next_step="Review whether long-lived public-key signing, identity, or TLS paths need a documented PQC/hybrid migration plan.",
            )
        )
    return sorted(findings, key=lambda finding: finding.overall_score, reverse=True)


def load_suppressions(path: Path | None) -> list[dict[str, object]]:
    if path is None:
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"could not read suppression file {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in suppression file {path}: {exc}") from exc
    entries = data.get("suppressions") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise ValueError("suppression file must contain a 'suppressions' list")
    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            raise ValueError(f"suppression entry {index} must be an object")
        for key in ("reason", "owner", "expires"):
            value = entry.get(key)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"suppression entry {index} requires non-empty '{key}'")
        match = entry.get("match")
        if not isinstance(match, dict) or not match:
            raise ValueError(f"suppression entry {index} requires non-empty object 'match'")
    return entries


def apply_suppressions(findings: list[Finding], suppressions: list[dict[str, object]]) -> list[Finding]:
    if not suppressions:
        return findings
    for finding in findings:
        for entry in suppressions:
            match = entry.get("match", {})
            if isinstance(match, dict) and suppression_matches(finding, match):
                finding.suppression_status = "suppressed"
                finding.suppression_reason = str(entry.get("reason", ""))
                finding.suppression_owner = str(entry.get("owner", ""))
                finding.suppression_expires = str(entry.get("expires", ""))
                break
    return findings


def suppression_matches(finding: Finding, match: dict[str, object]) -> bool:
    checks = {
        "finding_id": finding.finding_id,
        "verdict": finding.verdict,
        "primitive_or_protocol": finding.primitive_or_protocol,
        "top_context_kind": finding.top_context_kind,
        "evidence_grade": finding.evidence_grade,
    }
    for key, expected in match.items():
        if key == "path_prefix":
            if not finding.top_evidence_path.startswith(str(expected)):
                return False
            continue
        if key not in checks or str(checks[key]) != str(expected):
            return False
    return True


def classify_verdict(category: str, primitive: str, items: list[Evidence], lifecycle_items: list[Evidence], has_pqc: bool) -> str:
    if category == "pqc_signal":
        return "inventory_only"
    runtime_items = [item for item in items if item.context_kind in RUNTIME_CONTEXTS]
    if not runtime_items:
        return "inventory_only"
    if any(item.matched_text.startswith("-----BEGIN") for item in runtime_items):
        return "hardcoded_crypto_material"
    weak_tls = category == "tls" and any(item.matched_text.upper() in {"TLSV1", "TLSV1.0", "TLSV1.1", "CERT_NONE"} or item.matched_text in {"rejectUnauthorized", "InsecureSkipVerify", "NODE_TLS_REJECT_UNAUTHORIZED"} for item in runtime_items)
    unsafe_jwt = category == "jwt" and any(item.matched_text.lower() in {"none", "hs256"} for item in runtime_items)
    if weak_tls or unsafe_jwt:
        return "weak_or_legacy_algorithm"
    if category in {"rsa", "ecdsa", "secp256k1", "jwt", "tls", "ssh_key"} and lifecycle_items:
        return "migration_review"
    if category in {"rsa", "ecdsa", "secp256k1"} and not has_pqc:
        return "migration_review"
    return "inventory_only"


def context_rank(ctx: str) -> int:
    return {
        "runtime": 5,
        "manifest": 3,
        "lockfile": 2,
        "test": 1,
        "fixture": 1,
        "docs": 1,
        "example": 1,
        "generated": 1,
        "vendor": 1,
        "tooling": 1,
        "catalog": 1,
        "unknown": 0,
    }.get(ctx, 0)


def claim_details_for(verdict: str, items: list[Evidence], runtime_items: list[Evidence]) -> dict[str, str]:
    contexts = ", ".join(sorted({item.context_kind for item in items}))
    if verdict == "inventory_only" and not runtime_items:
        return {
            "claim_state": "local_signal",
            "what_is_certified": f"Passive static evidence was found only in non-runtime context(s): {contexts}.",
            "what_is_not_certified": "No runtime usage, vulnerability, exploitability, or migration blocker is certified.",
            "nearest_baseline": "Passive local pattern inventory with context downgrade.",
            "feedback_if_downgraded": "Treat as inventory_only until runtime/source evidence is added or verified.",
        }
    if verdict == "hardcoded_crypto_material":
        return {
            "claim_state": "local_signal",
            "what_is_certified": "A runtime-context line matched hardcoded crypto material syntax.",
            "what_is_not_certified": "The scanner does not use, validate, recover, or test key material and does not prove exploitability.",
            "nearest_baseline": "Passive local pattern inventory; verifier must confirm the line before maintainer-facing claims.",
            "feedback_if_downgraded": "Downgrade if verifier finds docs/test/generated/vendor context or line mismatch.",
        }
    if verdict in {"migration_review", "weak_or_legacy_algorithm"}:
        return {
            "claim_state": "local_signal",
            "what_is_certified": "Runtime-context static evidence matched a crypto migration or configuration review pattern.",
            "what_is_not_certified": "This is not proof of vulnerability, exploitability, reachable production use, or a migration blocker.",
            "nearest_baseline": "Passive local pattern inventory; runtime ownership and lifecycle must be reviewed manually.",
            "feedback_if_downgraded": "Downgrade to inventory_only if verifier confirms only docs/test/vendor/generated/lockfile evidence.",
        }
    return {
        "claim_state": "local_signal",
        "what_is_certified": "Passive static crypto inventory evidence was found.",
        "what_is_not_certified": "No exploitability, runtime reachability, or migration blocker is certified.",
        "nearest_baseline": "Passive local pattern inventory.",
        "feedback_if_downgraded": "Keep as inventory unless stronger runtime evidence is verified.",
    }


def evidence_ledger_for(verdict: str, items: list[Evidence], runtime_items: list[Evidence], lifecycle_items: list[Evidence]) -> dict[str, str]:
    if not runtime_items:
        contexts = ", ".join(sorted({item.context_kind for item in items}))
        return {
            "evidence_grade": "weak_context_inventory",
            "downgrade_reason": f"Evidence appears only in non-runtime context(s): {contexts}.",
            "promotion_requirements": "Add or verify runtime-classified source evidence before promoting beyond inventory-only.",
        }
    if all(item.context_kind in DEPENDENCY_CONTEXTS for item in items):
        return {
            "evidence_grade": "dependency_inventory",
            "downgrade_reason": "Evidence is dependency metadata only.",
            "promotion_requirements": "Map the dependency to runtime import/call evidence before migration-review promotion.",
        }
    if verdict == "inventory_only":
        return {
            "evidence_grade": "runtime_static_inventory",
            "downgrade_reason": "Runtime-classified evidence exists, but no lifecycle or review verdict condition was met.",
            "promotion_requirements": "Verify ownership, call path, and key/protocol lifetime before treating as migration review.",
        }
    if verdict == "hardcoded_crypto_material":
        return {
            "evidence_grade": "verifier_required",
            "downgrade_reason": "Not downgraded by scanner; line-level verifier must confirm context before maintainer-facing use.",
            "promotion_requirements": "Verifier must confirm the line, redact material, and keep any response to defensive cleanup/review.",
        }
    if lifecycle_items:
        return {
            "evidence_grade": "runtime_static_lifecycle_signal",
            "downgrade_reason": "Not downgraded by scanner; lifecycle terms appeared in runtime-classified source.",
            "promotion_requirements": "Verify the call path, ownership, expected lifetime, and migration relevance manually.",
        }
    return {
        "evidence_grade": "runtime_static_review_signal",
        "downgrade_reason": "Not downgraded by scanner; runtime-classified source matched a review pattern.",
        "promotion_requirements": "Verifier must confirm line evidence and reviewer must confirm this is not docs/test/generated/vendor context.",
    }


def title_for(verdict: str, primitive: str) -> str:
    titles = {
        "inventory_only": f"{primitive} inventory signal",
        "migration_review": f"{primitive} migration review target",
        "hardcoded_crypto_material": "Hardcoded crypto material review target",
        "weak_or_legacy_algorithm": f"{primitive} weak or legacy configuration review",
        "pqc_absent_but_relevant": "No visible PQC/hybrid migration signal",
    }
    return titles.get(verdict, f"{primitive} static finding")


def impact_area_for(items: list[Evidence]) -> str:
    text = " ".join(item.snippet for item in items)
    if re.search(r"\b(jwt|token|auth|session|issuer|jwks|saml)\b", text, re.IGNORECASE):
        return "identity_or_auth"
    if re.search(r"\b(wallet|address|secp256k1|privateKeyToAccount)\b", text, re.IGNORECASE):
        return "wallet_or_signing"
    if re.search(r"\b(tls|certificate|x509|csr|keystore)\b", text, re.IGNORECASE):
        return "tls_or_certificate"
    return "crypto_inventory"


def recommendation_for(verdict: str) -> str:
    if verdict == "hardcoded_crypto_material":
        return "Review the referenced file for hardcoded crypto material; do not test or use any key material found by the scanner."
    if verdict == "weak_or_legacy_algorithm":
        return "Review the referenced algorithm or TLS/JWT configuration and document an approved replacement if needed."
    if verdict == "migration_review":
        return "Review whether this public-key crypto path is long-lived and needs a PQC/hybrid migration plan."
    if verdict == "pqc_absent_but_relevant":
        return "Review whether long-lived public-key signing, identity, or TLS paths need a documented PQC/hybrid migration plan."
    return "Keep as inventory evidence; verify context before making maintainer-facing claims."


def write_csv(path: Path, rows: Iterable[dict[str, object]], columns: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            writer.writerow({column: row.get(column, "") for column in columns})


def write_graph(path: Path, repo_id: str, evidence: list[Evidence], findings: list[Finding]) -> None:
    def node_id(value: str) -> str:
        return "n_" + hashlib.sha1(value.encode("utf-8")).hexdigest()[:12]

    lines = ["digraph crypto_radar {", "  rankdir=LR;", f'  {node_id(repo_id)} [label="{dot_escape(repo_id)}", type="repository"];']
    seen_nodes = {node_id(repo_id)}
    seen_edges: set[tuple[str, str, str]] = set()
    for item in evidence:
        file_node = node_id("file:" + item.file_path)
        primitive_node = node_id("primitive:" + item.primitive_or_protocol)
        if file_node not in seen_nodes:
            seen_nodes.add(file_node)
            lines.append(f'  {file_node} [label="{dot_escape(item.file_path)}", type="{item.context_kind}"];')
            seen_edges.add((node_id(repo_id), file_node, "contains"))
        if primitive_node not in seen_nodes:
            seen_nodes.add(primitive_node)
            lines.append(f'  {primitive_node} [label="{dot_escape(item.primitive_or_protocol)}", type="primitive"];')
        seen_edges.add((file_node, primitive_node, graph_edge_kind_for(item)))
    if any(f.verdict == "pqc_absent_but_relevant" for f in findings):
        pqc_node = node_id("migration_gap:pqc")
        if pqc_node not in seen_nodes:
            lines.append(f'  {pqc_node} [label="no visible PQC/hybrid signal", type="migration_signal"];')
        seen_edges.add((node_id(repo_id), pqc_node, "lacks_migration_signal"))
    for src, dst, label in sorted(seen_edges):
        lines.append(f'  {src} -> {dst} [label="{label}"];')
    lines.append("}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def dot_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def graph_edge_kind_for(item: Evidence) -> str:
    if item.source_kind == "dependency_inventory":
        return "depends_on"
    if item.source_kind == "import_dependency_usage":
        return "imports"
    if re.search(r"\b(sign|signature|privateKey|issuer|package signing|release signing)\b", item.snippet, re.IGNORECASE):
        return "signs_with"
    if re.search(r"\b(verify|verifies|jwks|certificate|x509|publicKey|rejectUnauthorized)\b", item.snippet, re.IGNORECASE):
        return "verifies_with"
    if re.search(r"\b(TLS|ssl_protocols|minVersion|maxVersion|ciphers)\b", item.snippet, re.IGNORECASE):
        return "uses_protocol"
    return "mentions"


def build_review_paths(evidence: list[Evidence], findings: list[Finding]) -> list[dict[str, object]]:
    findings_by_primitive: dict[str, list[Finding]] = {}
    for finding in findings:
        findings_by_primitive.setdefault(finding.primitive_or_protocol, []).append(finding)
    by_file: dict[str, list[Evidence]] = {}
    for item in evidence:
        by_file.setdefault(item.file_path, []).append(item)

    paths: list[dict[str, object]] = []
    for file_path, items in sorted(by_file.items()):
        contexts = sorted({item.context_kind for item in items})
        primitives = sorted({item.primitive_or_protocol for item in items})
        path_findings = [finding for primitive in primitives for finding in findings_by_primitive.get(primitive, [])]
        verdicts = sorted({finding.verdict for finding in path_findings})
        edge_kinds = sorted({graph_edge_kind_for(item) for item in items})
        runtime_evidence = [item for item in items if item.context_kind in RUNTIME_CONTEXTS]
        dependency_edges = [edge for edge in edge_kinds if edge in {"imports", "depends_on"}]
        lifecycle_edges = [edge for edge in edge_kinds if edge in {"signs_with", "verifies_with", "uses_protocol"}]
        category_count = len({item.category for item in items})
        max_finding_score = max((finding.overall_score for finding in path_findings), default=0)
        downgrade_only = not runtime_evidence
        score = 0
        score += len(primitives) * 8
        score += category_count * 5
        score += len(dependency_edges) * 7
        score += len(lifecycle_edges) * 10
        score += max_finding_score * 0.4
        if runtime_evidence:
            score += 15
        if any(verdict in {"hardcoded_crypto_material", "weak_or_legacy_algorithm", "migration_review"} for verdict in verdicts):
            score += 15
        if downgrade_only:
            score *= 0.45
        paths.append(
            {
                "file_path": file_path,
                "rank_score": round(score, 2),
                "contexts": contexts,
                "edge_kinds": edge_kinds,
                "edge_basis": "inferred_static_line_signal",
                "primitive_or_protocols": primitives,
                "verdicts": verdicts,
                "evidence_count": len(items),
                "runtime_evidence_count": len(runtime_evidence),
                "dependency_edge_count": len(dependency_edges),
                "lifecycle_edge_count": len(lifecycle_edges),
                "primitive_count": len(primitives),
                "category_count": category_count,
                "max_finding_score": round(max_finding_score, 2),
                "downgrade_only": downgrade_only,
                "claim_state": "local_signal",
                "review_reason": review_reason_for(edge_kinds, contexts, verdicts, downgrade_only),
            }
        )
    return sorted(paths, key=lambda row: (row["rank_score"], row["file_path"]), reverse=True)


def review_reason_for(edge_kinds: list[str], contexts: list[str], verdicts: list[str], downgrade_only: bool) -> str:
    if downgrade_only:
        return "Inventory-only path unless runtime evidence is verified."
    if "signs_with" in edge_kinds or "verifies_with" in edge_kinds:
        return "Inferred static signing/verification review edge in runtime-classified source; verify ownership and migration relevance manually."
    if "imports" in edge_kinds:
        return "Inferred runtime crypto dependency usage; map calling paths before migration claims."
    if any(verdict in {"hardcoded_crypto_material", "weak_or_legacy_algorithm"} for verdict in verdicts):
        return "Runtime static finding should be verified line-by-line before maintainer-facing claims."
    return f"Static crypto inventory path in context(s): {', '.join(contexts)}."


def write_reports(
    root: Path,
    out_dir: Path,
    evidence: list[Evidence],
    findings: list[Finding],
    repo_id: str | None = None,
    pattern_catalog: Path = DEFAULT_PATTERN_CATALOG,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    repo_id = repo_id or repo_id_for(root)
    legacy_maintainer_note = out_dir / "maintainer_note.md"
    if legacy_maintainer_note.exists():
        legacy_maintainer_note.unlink()
    evidence_dir = out_dir / "evidence"
    evidence_dir.mkdir(exist_ok=True)
    inventory_rows = [{k: v for k, v in asdict(item).items() if k != "snippet"} for item in evidence]
    finding_rows = [asdict(item) for item in findings]
    review_paths = build_review_paths(evidence, findings)
    write_csv(out_dir / "crypto_inventory.csv", inventory_rows, INVENTORY_COLUMNS)
    write_csv(out_dir / "crypto_findings.csv", finding_rows, FINDING_COLUMNS)
    write_csv(out_dir / "crypto_review_paths.csv", review_paths, REVIEW_PATH_COLUMNS)
    (evidence_dir / "evidence.jsonl").write_text(
        "".join(json.dumps(asdict(item), ensure_ascii=False) + "\n" for item in evidence),
        encoding="utf-8",
    )
    write_graph(out_dir / "crypto_graph.dot", repo_id, evidence, findings)
    (out_dir / "crypto_findings.sarif").write_text(json.dumps(render_sarif(repo_id, findings), indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / "crypto_cbom.json").write_text(json.dumps(render_cbom(repo_id, evidence, findings), indent=2, ensure_ascii=False), encoding="utf-8")
    report = {
        "repo": {"id": repo_id, "path": str(root.resolve())},
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "scanner_version": SCANNER_VERSION,
        "pattern_catalog": {
            "path": str(pattern_catalog),
            "version": pattern_catalog_version(pattern_catalog),
            "sha256": file_sha256(pattern_catalog),
        },
        "claim_boundary": CLAIM_BOUNDARY,
        "summary": {
            "evidence_count": len(evidence),
            "finding_count": len(findings),
            "verdict_counts": count_by(finding_rows, "verdict"),
            "suppression_counts": count_by(finding_rows, "suppression_status"),
            "categories": count_by(inventory_rows, "category"),
            "context_counts": count_by(inventory_rows, "context_kind"),
        },
        "findings": finding_rows,
        "review_paths": review_paths,
        "evidence": [asdict(item) for item in evidence],
        "verifier": {"status": "not_run", "note": "MVP output requires verifier review before maintainer-facing claims."},
        "limitations": [
            "Static pattern matching can produce false positives and false negatives.",
            "The scanner does not contact live services and does not test whether any key, token, or endpoint works.",
            "Absence of a PQC signal means no matching local repository text was found by this scanner, not proof that no plan exists.",
        ],
    }
    (out_dir / "qday_risk_report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / "qday_risk_report.md").write_text(render_markdown_report(report), encoding="utf-8")
    (out_dir / "internal_review_note.md").write_text(render_internal_review_note(report), encoding="utf-8")


def count_by(rows: list[dict[str, object]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(key, ""))
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def render_sarif(repo_id: str, findings: list[Finding]) -> dict[str, object]:
    rules: dict[str, dict[str, object]] = {}
    results: list[dict[str, object]] = []
    for finding in findings:
        if not finding.top_evidence_path:
            continue
        rule_id = finding.verdict
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": title_for(finding.verdict, finding.primitive_or_protocol),
                "shortDescription": {"text": "Passive crypto/PQC migration review signal"},
                "fullDescription": {"text": "Static evidence only; verifier and manual context review are required before maintainer-facing claims."},
                "help": {"text": recommendation_for(finding.verdict)},
                "properties": {"claim_state": "local_signal"},
            },
        )
        results.append(
            {
                "ruleId": rule_id,
                "level": sarif_level_for(finding.verdict),
                "message": {
                    "text": (
                        f"{finding.title}. Evidence grade: {finding.evidence_grade}. "
                        f"Promotion requirements: {finding.promotion_requirements}. "
                        "This is a passive static review signal, not proof of exploitability."
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.top_evidence_path},
                            "region": {"startLine": finding.top_evidence_line},
                        }
                    }
                ],
                "properties": {
                    "repo_id": repo_id,
                    "verdict": finding.verdict,
                    "evidence_grade": finding.evidence_grade,
                    "claim_state": finding.claim_state,
                    "downgrade_reason": finding.downgrade_reason,
                    "promotion_requirements": finding.promotion_requirements,
                    "suppression_status": finding.suppression_status,
                    "suppression_reason": finding.suppression_reason,
                    "suppression_owner": finding.suppression_owner,
                    "suppression_expires": finding.suppression_expires,
                    "what_is_certified": finding.what_is_certified,
                    "what_is_not_certified": finding.what_is_not_certified,
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "crypto-pqc-migration-radar",
                        "informationUri": "https://example.invalid/crypto-pqc-migration-radar",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {
                    "repo_id": repo_id,
                    "claim_boundary": CLAIM_BOUNDARY,
                },
            }
        ],
    }


def sarif_level_for(verdict: str) -> str:
    if verdict in {"hardcoded_crypto_material", "weak_or_legacy_algorithm", "migration_review"}:
        return "warning"
    return "note"


def render_cbom(repo_id: str, evidence: list[Evidence], findings: list[Finding]) -> dict[str, object]:
    finding_by_primitive: dict[str, list[Finding]] = {}
    for finding in findings:
        finding_by_primitive.setdefault(finding.primitive_or_protocol, []).append(finding)
    by_component: dict[tuple[str, str], list[Evidence]] = {}
    for item in evidence:
        by_component.setdefault((item.category, item.primitive_or_protocol), []).append(item)

    components: list[dict[str, object]] = []
    for index, ((category, primitive), items) in enumerate(sorted(by_component.items()), start=1):
        related = finding_by_primitive.get(primitive, [])
        contexts = sorted({item.context_kind for item in items})
        components.append(
            {
                "type": "cryptographic-asset",
                "bom-ref": f"crypto:{index}:{category}:{primitive}".replace(" ", "_"),
                "name": primitive,
                "cryptoProperties": {
                    "assetType": category,
                    "contexts": contexts,
                    "evidenceCount": len(items),
                    "sourceKinds": sorted({item.source_kind for item in items}),
                    "claimState": "local_signal",
                    "evidenceGrades": sorted({finding.evidence_grade for finding in related}) if related else ["raw_evidence_only"],
                    "verdicts": sorted({finding.verdict for finding in related}) if related else [],
                },
                "evidence": [
                    {
                        "file": item.file_path,
                        "line": item.line,
                        "context": item.context_kind,
                        "matchedText": item.matched_text,
                    }
                    for item in items[:10]
                ],
            }
        )
    return {
        "bomFormat": "CryptoBOM",
        "specVersion": "0.1",
        "metadata": {
            "component": {"name": repo_id, "type": "repository"},
            "claimBoundary": CLAIM_BOUNDARY,
            "whatIsNotProven": "This CBOM-style export is passive static inventory, not proof of exploitability, runtime reachability, or vulnerability.",
        },
        "components": components,
    }


def render_markdown_report(report: dict[str, object]) -> str:
    repo = report["repo"]
    pattern_catalog = report["pattern_catalog"]
    summary = report["summary"]
    findings = report["findings"]
    review_paths = report["review_paths"]
    evidence = report["evidence"]
    lines = [
        "# Crypto/PQC Migration Radar Report",
        "",
        "## 1. Scope",
        "",
        CLAIM_BOUNDARY,
        "",
        f"- Repository: `{repo['path']}`",
        f"- Scanner version: `{report['scanner_version']}`",
        f"- Pattern catalog: `{pattern_catalog['path']}` version `{pattern_catalog['version']}` SHA-256 `{pattern_catalog['sha256']}`",
        f"- Scan timestamp: `{report['scan_timestamp']}`",
        "",
        "## 2. Summary",
        "",
        f"- Evidence rows: {summary['evidence_count']}",
        f"- Findings: {summary['finding_count']}",
        f"- Verdict counts: `{json.dumps(summary['verdict_counts'], sort_keys=True)}`",
        f"- Suppression counts: `{json.dumps(summary['suppression_counts'], sort_keys=True)}`",
        f"- Context counts: `{json.dumps(summary['context_counts'], sort_keys=True)}`",
        "",
        "## 3. Top Findings",
        "",
    ]
    if findings:
        for finding in findings[:10]:
            lines.append(
                f"- `{finding['finding_id']}` `{finding['verdict']}` score {finding['overall_score']}: "
                f"{finding['title']} at `{finding['top_evidence_path']}:{finding['top_evidence_line']}` "
                f"context `{finding['top_context_kind']}` grade `{finding['evidence_grade']}`. "
                f"Promotion: {finding['promotion_requirements']}"
            )
    else:
        lines.append("- No crypto/PQC pattern evidence found.")
    lines.extend(["", "## 4. Top Review Paths", ""])
    if review_paths:
        for path in review_paths[:10]:
            lines.append(
                f"- `{path['file_path']}` score {path['rank_score']}: "
                f"edges `{','.join(path['edge_kinds'])}` contexts `{','.join(path['contexts'])}`. "
                f"Basis `{path['edge_basis']}`. {path['review_reason']}"
            )
    else:
        lines.append("- No review paths produced.")
    lines.extend(["", "## 5. Evidence", ""])
    for item in evidence[:25]:
        lines.append(
            f"- `{item['file_path']}:{item['line']}` `{item['category']}` matched `{item['matched_text']}` "
            f"context `{item['context_kind']}` source `{item['source_kind']}` confidence {item['confidence']}: {item['snippet']}"
        )
    if len(evidence) > 25:
        lines.append(f"- Additional evidence rows omitted here; see `crypto_inventory.csv` and `evidence/evidence.jsonl`.")
    lines.extend(
        [
            "",
            "## 6. What This Does Not Prove",
            "",
            "- It does not prove exploitability.",
            "- It does not prove any production system is vulnerable.",
            "- It does not show that private keys can be recovered or signatures forged.",
            "",
            "## 7. Recommended Review Steps",
            "",
            "- Verify every high-priority line in local context.",
            "- Downgrade docs/test/example/generated/vendor and lockfile-only evidence to inventory-only unless runtime evidence is verified.",
            "- Treat graph edge labels as inferred static review edges, not semantic proof of runtime signing, verification, dependency reachability, or vulnerability.",
            "- Treat manifest and lockfile matches as dependency inventory; treat crypto imports as source dependency usage, not proof of vulnerability.",
            "- For long-lived signing, identity, wallet, certificate, or TLS paths, document migration ownership and PQC/hybrid readiness.",
            "",
            "## 8. Claim Discipline",
            "",
            "- what_is_certified: passive static evidence at cited file/line and scanner-level context classification.",
            "- what_is_not_certified: exploitability, production reachability, key validity, or that the repository is vulnerable.",
            "- claim_state: `local_signal` until verifier review and any baseline/manual ownership review are complete.",
            "- evidence_grade: scanner-side evidence maturity label; it is not a vulnerability severity.",
            "- promotion_requirements: verifier/manual checks needed before a stronger maintainer-facing claim.",
            "- nearest_baseline: passive local pattern inventory with context downgrade.",
            "- feedback_if_downgraded: keep downgraded rows as inventory evidence and require runtime/source evidence before promotion.",
            "",
            "## 9. Reproduction Command",
            "",
            "```powershell",
            f"python .\\crypto_pqc_radar.py --root <repo> --out-dir <out-dir> --pattern-catalog \"{pattern_catalog['path']}\"",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def render_internal_review_note(report: dict[str, object]) -> str:
    findings = [
        finding
        for finding in report["findings"]
        if finding["verdict"] != "inventory_only" and finding["top_evidence_path"] and finding.get("suppression_status") != "suppressed"
    ]
    lines = [
        "Internal passive static crypto migration review note:",
        "",
        CLAIM_BOUNDARY,
        "",
        "Status: not verifier-approved; do not send as a maintainer-facing note.",
        "",
    ]
    if not findings:
        lines.append("The scan produced inventory evidence but no verifier-ready migration review finding.")
    else:
        for finding in findings[:3]:
            lines.append(
                f"- Review `{finding['top_evidence_path']}:{finding['top_evidence_line']}`: "
                f"{finding['title']} (`{finding['verdict']}`)."
            )
    lines.append("")
    lines.append("Suggested next step: run the verifier and use only verifier-approved findings for maintainer-facing notes.")
    return "\n".join(lines)


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(
    root: Path,
    out_dir: Path,
    repo_id: str | None = None,
    pattern_catalog: Path = DEFAULT_PATTERN_CATALOG,
    suppressions: Path | None = None,
) -> tuple[list[Evidence], list[Finding]]:
    evidence = scan_repo(root, repo_id=repo_id, pattern_catalog=pattern_catalog)
    findings = dedupe_findings(evidence)
    findings = apply_suppressions(findings, load_suppressions(suppressions))
    write_reports(root, out_dir, evidence, findings, repo_id=repo_id, pattern_catalog=pattern_catalog)
    return evidence, findings


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Passive static Crypto/PQC migration radar.")
    parser.add_argument("--root", required=True, type=Path, help="Local repository root to scan.")
    parser.add_argument("--out-dir", required=True, type=Path, help="Directory for scanner outputs.")
    parser.add_argument("--repo-id", default=None, help="Optional stable repository identifier for report rows.")
    parser.add_argument("--pattern-catalog", default=DEFAULT_PATTERN_CATALOG, type=Path, help="JSON pattern catalog to load.")
    parser.add_argument("--suppressions", type=Path, help="Optional JSON suppression file. Suppressions mark findings but never delete raw evidence.")
    parser.add_argument("--force", action="store_true", help="Allow writing into a non-empty output directory.")
    parser.add_argument(
        "--fail-on",
        choices=("never", "findings", "review"),
        default="never",
        help="Exit non-zero for CI when any finding exists or when non-inventory review findings exist.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.root.exists() or not args.root.is_dir():
        raise SystemExit(f"--root must be an existing directory: {args.root}")
    if args.out_dir.exists() and not args.out_dir.is_dir():
        raise SystemExit(f"--out-dir exists but is not a directory: {args.out_dir}")
    if args.out_dir.exists() and any(args.out_dir.iterdir()) and not args.force:
        raise SystemExit(f"--out-dir is not empty; use --force to overwrite scanner outputs: {args.out_dir}")
    try:
        evidence, findings = run(args.root, args.out_dir, repo_id=args.repo_id, pattern_catalog=args.pattern_catalog, suppressions=args.suppressions)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    print(f"Wrote {len(evidence)} evidence rows and {len(findings)} findings to {args.out_dir}")
    if args.fail_on == "findings" and findings:
        return 2
    if args.fail_on == "review" and any(finding.verdict != "inventory_only" for finding in findings):
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
