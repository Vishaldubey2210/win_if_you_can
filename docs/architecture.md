# SLOPGUARD Architecture Specification

## 1. System Overview
SLOPGUARD is an AI Dependency Control Plane and Supply-Chain Firewall designed to sit between AI coding agents/LLM code generators and package registries.

### Core Principle
> **EXISTENCE != TRUST != FUTURE SAFETY**

Never reduce dependency security to a binary question of whether a package exists on a registry. SLOPGUARD operates on deterministic evidence collection, identity resolution, temporal memory of previously unresolved dependencies, and policy-as-code enforcement before any installation action can occur.

## 2. Canonical Pipeline
The dependency evaluation lifecycle follows a strict sequence:

```
[SOURCE CODE / MANIFEST / AGENT ACTION]
                 ↓
           1. EXTRACT (AST-first, parser-based, manifest parsing)
                 ↓
           2. IDENTITY (Normalization, alias mappings cv2 -> opencv-python)
                 ↓
           3. VERIFY (Registry verification: PyPI, npm; network failure != 404)
                 ↓
           4. EVIDENCE (Metadata, releases, timestamps, repository linkage, OSV)
                 ↓
           5. TRUST (Version-level trust, typosquat detection, age, signals)
                 ↓
           6. MEMORY (Temporal phantom tracking: NOT_FOUND -> WATCH -> APPEARED)
                 ↓
           7. GATE (Deterministic Policy-as-Code: ALLOW / HOLD / BLOCK / ALERT)
```

## 3. Component Architecture

### 3.1 Extraction Engine (`slopguard.extraction`)
- **Python Extractor**: AST-based parsing using Python's standard `ast` module. Distinguishes stdlib, direct imports (`import x`, `from x import y`), relative imports, and alias bindings.
- **JavaScript/TypeScript Extractor**: Parser-based token and AST traversal for ES Modules (`import ... from "pkg"`, `import "pkg"`) and CommonJS (`require("pkg")`).
- **Manifest Parsers**: Structured parsers for `requirements.txt`, `pyproject.toml`, `package.json`, and lockfiles.

### 3.2 Identity Resolution Engine (`slopguard.identity`)
- Separates `import_name` from `package_name`.
- Normalized package lookup rules (PEP 503 normalization for PyPI, lowercase/scoped rules for npm).
- High-confidence alias graph (e.g. `PIL -> pillow`, `cv2 -> opencv-python`, `yaml -> pyyaml`, `sklearn -> scikit-learn`, `dateutil -> python-dateutil`).
- Distinguishes standard library packages (e.g. `sys`, `os`, `pathlib`, `crypto` in Node) from third-party registry packages.

### 3.3 Registry Engine (`slopguard.registry`)
- Registry adapters with bounded retries, exponential backoff, rate limit handling, and distinct error classifications:
  - `FOUND`
  - `NOT_FOUND` (only with definitive 404 evidence)
  - `RATE_LIMITED` (429) -> triggers HOLD/REVIEW
  - `SERVER_ERROR` (500, 502, 503) -> triggers HOLD/REVIEW
  - `TIMEOUT` -> triggers HOLD/REVIEW
  - `MALFORMED_RESPONSE` -> triggers HOLD/REVIEW
- Adapters for PyPI (`https://pypi.org/pypi/{package}/json`) and npm (`https://registry.npmjs.org/{package}`).

### 3.4 Evidence Engine & Graph (`slopguard.evidence`)
- Structured evidence record storage:
  - `RegistryEvidence` (release count, upload dates, author, maintainers, home page, repository URL).
  - `SecurityAdvisories` (OSV queries, CVEs).
  - `TemporalEvidence` (first seen, last seen, state transitions).
  - `TyposquatEvidence` (distance metrics, confusable tokens, closest known popular packages).
- Graph model: `Import -> Package -> Release -> Maintainer -> Repository -> Advisory`.

### 3.5 Trust Engine (`slopguard.trust`)
- Multi-dimensional, explainable trust evaluation:
  - Identity confidence
  - Registry verification status
  - Package age and release frequency
  - Typosquatting score against top registry packages
  - Vulnerability / Advisory status
- Never output an arbitrary, opaque "AI trust score". Every evaluation dimension has documented reasons and underlying raw evidence.

### 3.6 Temporal Phantom Memory (`slopguard.memory`)
- Tracks packages that were observed but unresolved (`NOT_FOUND` or phantom dependencies).
- States:
  - `NOT_FOUND`
  - `WATCH`
  - `APPEARED` (a previously missing package is now published)
  - `RESOLVED`
- An appeared phantom dependency raises an immediate security `ALERT` requiring human review (combating supply-chain dependency combative pre-registration / dependency hallucination exploitation).

### 3.7 Repair & Remediation Engine (`slopguard.repair`)
- API and context-aware candidate ranking when a package is not found or is a typosquat.
- Rescan-on-repair loop: Repairs must be re-parsed and re-evaluated through the complete pipeline before acceptance.

### 3.8 Deterministic Policy Gate (`slopguard.policy`)
- Policy-as-Code engine evaluating evidence without LLM hallucination:
  - `ALLOW`: Identity verified, registry confirmed, trust metrics satisfied, zero active blocking advisories.
  - `HOLD / REVIEW`: Transient registry failure, new package with minimal release history, ambiguous identity.
  - `BLOCK`: Definite missing package, typosquatting detected, unresolvable identity, active severe advisory.
  - `ALERT`: Temporal phantom state change detected.

### 3.9 Presentation & Interfaces
- **REST API**: FastAPI application exposing `/api/v1/scan`, `/api/v1/verify`, `/api/v1/phantoms`, `/api/v1/policies`.
- **CLI**: `slopguard` command-line tool with human and JSON output modes.
- **Frontend**: Developer-focused dashboard with Overview, Scan, Dependencies, Dependency Detail, Evidence Graph, Phantom Timeline, and Policy management.

## 4. Repository Layout
```
slopguard/
├── extraction/         # AST and manifest dependency extraction
├── identity/           # Identity mappings, normalization, stdlib catalogs
├── registry/           # PyPI, npm adapters with error isolation
├── evidence/           # Evidence collection and graph models
├── trust/              # Multi-dimensional trust & typosquat evaluators
├── memory/             # Temporal phantom watchlist and persistence
├── repair/             # Contextual repair candidate generator and patcher
├── policy/             # Deterministic gate & policy-as-code
├── cli/                # Command-line interface
├── api/                # FastAPI application endpoints
apps/
└── frontend/           # Modern React/TypeScript dashboard
tests/
├── unit/               # Fast component unit tests
├── integration/        # Pipeline integration tests
├── security/           # Typosquat, phantom exploit, adversarial tests
└── benchmark/          # Corpus benchmarks (REAL, PHANTOM, TRICKY, FAILURE)
docs/
├── architecture.md     # This document
├── threat-model.md     # Security threat analysis
└── adr/                # Architectural Decision Records
```
