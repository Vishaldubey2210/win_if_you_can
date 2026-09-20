# SLOPGUARD

**AI Dependency Control Plane / Supply-Chain Firewall**

[![PyPI Version](https://img.shields.io/pypi/v/slopguard-ai.svg)](https://pypi.org/project/slopguard-ai/)
[![Python Version](https://img.shields.io/pypi/pyversions/slopguard-ai.svg)](https://pypi.org/project/slopguard-ai/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-62%20passed-brightgreen.svg)](tests/)

> **Core Principle:** `EXISTENCE != TRUST != FUTURE SAFETY`

**SLOPGUARD** (`slopguard-ai`) is an enterprise-grade, pre-install security control plane and supply-chain firewall designed to sit between AI coding agents (Claude, Devin, Copilot, Cursor) / AI-generated source code and package registries (PyPI, npm). It validates dependency identity, collects structured evidence, evaluates multi-dimensional trust signals, tracks temporal package transitions (phantoms), suggests contextual repairs, enforces deterministic Policy-as-Code, and blocks malicious or hallucinated dependency installations before package code can ever execute.

---

## Quickstart (First 30 Seconds)

### 1. Install from PyPI

```bash
pip install slopguard-ai
```

> **Note:** The distribution name is `slopguard-ai`, the CLI command is `slopguard`, and the Python import package is `import slopguard`.

### 2. Verify Your First Package

```bash
slopguard verify requests
```

Output:
```text
+------ Registry Verification Evidence -------+
| Package: requests (pypi)                    |
| Status: FOUND                               |
| Latency: 344.2ms | Releases: 163            |
| Latest Version: 2.34.2                      |
| Repository: https://github.com/psf/requests |
+---------------------------------------------+
```

### 3. Scan a File or Repository

```bash
# Scan a single source file
slopguard scan app.py

# Scan an entire directory with the strict CI policy profile
slopguard scan . --profile strict_ci
```

---

## The Threat: Why AI-Generated Dependencies Are Different

Autonomous AI coding agents frequently hallucinate dependencies or confuse internal module imports with public distribution names. Attackers exploit this via **phantom pre-registration attacks**:
1. AI model hallucinates a nonexistent package name (e.g. `langchain-hyper-fast-auth`).
2. Attacker monitors public repositories/datasets, registers that exact package name on PyPI/npm.
3. Attacker injects malicious execution hooks in `setup.py` or `install.js`.
4. AI agent executes `pip install langchain-hyper-fast-auth`, granting immediate Remote Code Execution (RCE) on the developer machine or CI runner.

Traditional SCA tools run *after* installation in CI/CD, which is too late. SLOPGUARD acts as an active, **pre-install firewall** that intercepts dependencies *before* they are resolved or executed.

---

## Architecture Pipeline

SLOPGUARD executes an immutable nine-stage pipeline:

```
[SOURCE CODE / MANIFEST / AGENT INSTALL COMMAND]
                     ↓
        1. EXTRACT (AST-first Python & JS/TS parser; manifest parsing)
                     ↓
        2. IDENTITY (PEP 503 canonical normalization; cv2 -> opencv-python)
                     ↓
        3. VERIFY (Resilient PyPI & npm adapters; network failure != 404)
                     ↓
        4. EVIDENCE (OSV vulnerabilities, repository linkage, provenance)
                     ↓
        5. TRUST (Unicode confusables, release velocity, typosquat distance)
                     ↓
        6. MEMORY (Temporal phantom tracking: NOT_FOUND -> WATCH -> APPEARED)
                     ↓
        7. REPAIR (Contextual candidate ranking & AST diff patch generator)
                     ↓
        8. RESCAN (Mandatory PATCH -> RESCAN -> VERIFY validation loop)
                     ↓
        9. POLICY & GATE (Deterministic Policy-as-Code: ALLOW / HOLD / BLOCK / ALERT)
```

---

## Example Policy Gate Outcomes

SLOPGUARD enforces deterministic policy outcomes based on empirical evidence:

### 1. `ALLOW` — Verified, Established Dependency
- **Scenario**: Source contains `import cv2` and `import requests`.
- **Reasoning**: `cv2` resolves to canonical `opencv-python` with 0.99 confidence. `requests` has 163 releases, 10+ years history, verified GitHub repository, and 0 active OSV vulnerabilities.
- **Verdict**: `ALLOW` (Risk: LOW / NONE).

### 2. `BLOCK` — Hallucinated Phantom or Dangerous Typosquat
- **Scenario**: Source contains `import langchain_hyper_fast_auth` or `import requets`.
- **Reasoning**: `langchain_hyper_fast_auth` returns HTTP 404 on PyPI. `requets` is detected as a Damerau-Levenshtein typosquat targeting `requests`.
- **Verdict**: `BLOCK` (Risk: HIGH / CRITICAL). Quarantine enforced; installation denied.

### 3. `HOLD / REVIEW` — Registry Outage Fail-Safe
- **Scenario**: PyPI returns HTTP 429 Too Many Requests or 503 Service Unavailable.
- **Reasoning**: **Registry failure is never converted into NOT_FOUND**. Rather than allowing unverified code or falsely reporting missing packages, SLOPGUARD fails safe.
- **Verdict**: `HOLD / REVIEW` (Requires human confirmation or retry).

### 4. `ALERT` — Pre-Registration Attack Detected
- **Scenario**: Package `target-phantom-corp` was previously missing (`NOT_FOUND`), but a newly registered version suddenly appears on PyPI.
- **Reasoning**: Temporal state change `NOT_FOUND -> APPEARED` signals high-probability dependency confusion or phantom hijacking.
- **Verdict**: `ALERT` (High-severity quarantine enforced).

---

## Production CLI Commands

| Command | Usage | Description |
|---|---|---|
| `slopguard scan <target>` | `slopguard scan app.py` | Scans source file, manifest, or directory and enforces policy gate. |
| `slopguard verify <pkg>` | `slopguard verify fastapi` | Authoritatively checks existence, release count, and version on registry. |
| `slopguard evidence <pkg>` | `slopguard evidence requests` | Retrieves full dossier: registry telemetry, live OSV advisories, and provenance. |
| `slopguard trust <pkg>` | `slopguard trust pydantic` | Evaluates multi-dimensional trust signals (age, velocity, typosquats). |
| `slopguard graph <pkg>` | `slopguard graph requests` | Queries directed Evidence Graph relations (`HOSTED_AT`, `HAS_RELEASE`, `AFFECTED_BY`). |
| `slopguard phantom list` | `slopguard phantom list` | Inspects the persistent Temporal Phantom Watchlist and state transitions. |
| `slopguard history <pkg>` | `slopguard history <pkg>` | Reconstructs historical observations and forensic audit logs. |
| `slopguard repair <dep>` | `slopguard repair cv2` | Proposes contextual candidate replacements and unified diff AST patches. |
| `slopguard rescan <file>` | `slopguard rescan app.py` | Rescans a patched file to enforce mandatory `PATCH -> RESCAN -> VERIFY` loop. |
| `slopguard policy check` | `slopguard policy check --profile enterprise` | Inspects and simulates active Policy-as-Code rules. |

---

## Policy Profiles

Configure SLOPGUARD via `--profile <name>`:

- **`DEVELOPMENT`**: Designed for local prototyping. Permits provisional trust and packages < 30 days old without known advisories.
- **`STRICT_CI`** *(Default)*: Zero-tolerance build gate for CI/CD pipelines. Blocks unresolved identities, packages with CVEs (CVSS $\ge 7.0$), and unreviewed phantoms.
- **`ENTERPRISE`**: Maximum hardening. Enforces verified provenance/attestation, blocks packages younger than 30 days, blocks all CVEs, and requires verified repository linkages.

---

## Running the Web Dashboard & API

SLOPGUARD includes an interactive dark-mode Single-Page Application (SPA) dashboard:

```bash
uvicorn slopguard.api.app:app --host 0.0.0.0 --port 8000
```

Open `http://localhost:8000` in your browser to inspect:
- Live Scan interactive terminal
- Evidence Graph relationship explorer
- Temporal Phantom Timeline
- Contextual Repair Center
- Audit Log reconstruction

---

## Local Development & Contributing

### 1. Clone & Setup

```bash
git clone https://github.com/slopguard/slopguard.git
cd slopguard

python -m venv .venv
# Windows:
.\.venv\Scripts\Activate.ps1
# Linux/macOS:
source .venv/bin/activate

pip install -e ".[dev]"
```

### 2. Run Tests & Self-Scan

```bash
# Run full test suite (62 tests)
pytest -v tests/

# Run supply-chain self-scan on SLOPGUARD's own dependencies
python scripts/ci_check.py pyproject.toml --profile strict_ci
```

### 3. Build & Package

```bash
python -m build
twine check dist/*
```

For complete instructions on TestPyPI and PyPI publishing, see the [PyPI & TestPyPI Distribution Guide](docs/publishing-guide.md).

---

## Documentation Index

- [Comprehensive Final Project Report (31 Sections)](docs/final-project-report.md)
- [Feature-by-Feature Audit Matrix](docs/final-feature-matrix.md)
- [90-Second Demonstration Script](docs/demo-script.md)
- [Technical Viva & Defense Reference (35 Q&As)](docs/viva-questions.md)
- [Release Readiness Checklist (RC-1)](docs/release-readiness.md)
- [PyPI Distribution & Publishing Guide](docs/publishing-guide.md)
- [Threat Model](docs/threat-model.md)
- [Architecture Specification](docs/architecture.md)

---

## License

SLOPGUARD is licensed under the [Apache License, Version 2.0](LICENSE).
