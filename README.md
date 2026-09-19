# SLOPGUARD

**AI Dependency Control Plane / Supply-Chain Firewall**

> **Core Principle:** `EXISTENCE != TRUST != FUTURE SAFETY`

SLOPGUARD is a pre-install security control plane for AI-generated code and autonomous coding agents. It intercepts package installations, extracts imports, resolves canonical identities, collects registry evidence, evaluates multi-dimensional trust, tracks temporal state transitions in previously unresolved packages (phantoms), and enforces deterministic Policy-as-Code.

---

## Architecture Pipeline

```
[SOURCE CODE / MANIFEST / AGENT ACTION]
                 ↓
           1. EXTRACT (AST-first, parser-based, manifest parsing)
                 ↓
           2. IDENTITY (Normalization, alias mappings cv2 -> opencv-python)
                 ↓
           3. VERIFY (Registry verification: PyPI, npm; network failure != 404)
                 ↓
           4. EVIDENCE (Metadata, releases, timestamps, repository linkage)
                 ↓
           5. TRUST (Version-level trust, typosquat detection, age, signals)
                 ↓
           6. MEMORY (Temporal phantom tracking: NOT_FOUND -> WATCH -> APPEARED)
                 ↓
           7. GATE (Deterministic Policy-as-Code: ALLOW / HOLD / BLOCK / ALERT)
```

---

## Key Features

- **AST-First Extraction**: Parses Python AST and JavaScript/TypeScript tokens without regex false-positives. Supports `requirements.txt`, `pyproject.toml`, and `package.json`.
- **Identity Graph & Alias Resolution**: Automatically resolves diverging names (e.g. `import cv2` → `opencv-python`, `import yaml` → `pyyaml`, `import PIL` → `pillow`).
- **Failure-Isolated Registry Adapters**: Respects rate limits, timeouts, and server errors; never conflates network outages with `404 NOT_FOUND`.
- **Damerau-Levenshtein Typosquat Detection**: Flags suspicious similarity to popular open-source packages (e.g., `requets` → `requests`).
- **Temporal Phantom Memory**: Tracks hallucinated dependencies. If an unresolved package is later registered (`NOT_FOUND` → `APPEARED`), an immediate `ALERT` is triggered to neutralize hallucination pre-registration exploits.
- **Deterministic Gate**: Policy decisions (`ALLOW`, `HOLD`, `BLOCK`, `ALERT`) are rule-based and auditable.

---

## Quickstart

### 1. Installation

```bash
# Clone the repository
git clone <repo-url>
cd win_if_you_can

# Create and activate virtual environment
python -m venv .venv
# On Windows:
.\.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install in editable mode with development tools
pip install -e ".[dev]"
```

### 2. Running the CLI

```bash
# Scan a Python file
slopguard scan demo/sample_projects/ai_generated_app.py

# Machine-readable JSON output
slopguard scan demo/sample_projects/ai_generated_app.py --json

# Direct package verification against registry
slopguard verify requests
slopguard verify express --ecosystem npm

# Inspect Temporal Phantom Watchlist
slopguard phantom list
```

### 3. Starting the REST API

```bash
uvicorn slopguard.api.app:app --host 0.0.0.0 --port 8000 --reload
```

Endpoints:
- `POST /api/v1/scan`: Scan source code or manifest content.
- `GET /api/v1/verify/{ecosystem}/{package_name}`: Inspect live registry evidence.
- `GET /api/v1/phantoms`: Query temporal watchlist.
- `GET /api/v1/health`: Service health check.

### 4. Running the Test Suite

```bash
pytest -v
```

---

## Documentation

- [Architecture Specification](file:///d:/Projects/win_if_you_can/docs/architecture.md)
- [Threat Model](file:///d:/Projects/win_if_you_can/docs/threat-model.md)
- [ADR 001: AST Extraction Over Regex](file:///d:/Projects/win_if_you_can/docs/adr/001-ast-over-regex.md)
- [ADR 002: Deterministic Policy Engine](file:///d:/Projects/win_if_you_can/docs/adr/002-deterministic-policy-engine.md)
- [ADR 003: LLM Explanations Without Verdict Authority](file:///d:/Projects/win_if_you_can/docs/adr/003-llm-not-final-verdict.md)
- [ADR 004: Temporal Phantom Memory](file:///d:/Projects/win_if_you_can/docs/adr/004-temporal-phantom-memory.md)
- [ADR 005: Distinction of Registry Outages](file:///d:/Projects/win_if_you_can/docs/adr/005-review-on-registry-failure.md)
