# SLOPGUARD

**AI Dependency Control Plane / Supply-Chain Firewall**

> **Core Principle:** `EXISTENCE != TRUST != FUTURE SAFETY`

SLOPGUARD is an enterprise-grade, pre-install security control plane designed to sit between AI coding agents / AI-generated source code and package registries (PyPI, npm). It validates dependency identity, collects structured evidence, evaluates multi-dimensional trust signals, tracks temporal package transitions (phantoms), suggests contextual repairs, enforces deterministic Policy-as-Code, and blocks malicious or hallucinated dependency installations before package code can ever execute.

---

## Architecture Pipeline

```
[SOURCE CODE / MANIFEST / AGENT ACTION]
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
           9. POLICY (Deterministic Policy-as-Code: ALLOW / HOLD / BLOCK / ALERT)
                 ↓
           10. GATE & AUDIT (Pre-install quarantine gate & decision reconstruction)
```

---

## Key Capabilities

1. **Quarantine Gate & AI Action Firewall**:
   - Intercepts both code repositories and proposed runtime agent installation actions (e.g., `pip install X`, `npm install Y`).
   - Hardened pre-install gate: no package installation proceeds if policy evaluates to `HOLD`, `REVIEW`, or `BLOCK`.
2. **Deterministic Policy-as-Code**:
   - Versioned, testable policy rules with configurable profiles:
     - `DEVELOPMENT`: Permissive for local rapid prototyping.
     - `STRICT_CI`: Zero-tolerance quarantine gate for CI/CD pipelines.
     - `ENTERPRISE`: Strict provenance, release age (quarantine < 30 days), and minimum release requirements.
3. **AST-First Parsing & Canonical Identity Resolution**:
   - Python AST and JavaScript/TypeScript token parsing eliminate comment and regex false-positives.
   - Built-in resolution graph maps diverging import names to official registry packages (e.g. `import cv2` → `opencv-python`, `import PIL` → `pillow`).
4. **Resilient Registry Isolation**:
   - Built-in exponential backoff, rate limiting, and TTL caching.
   - **Fail-Safe Posture**: HTTP 429, 5xx errors, and network timeouts are strictly routed to `HOLD / REVIEW`. They are **never** conflated with `NOT_FOUND`.
5. **Multi-Dimensional Trust & Typosquat Engine**:
   - Unicode confusable homoglyph detection (e.g., Cyrillic lookalikes `numpу`).
   - Damerau-Levenshtein similarity to top open-source libraries.
   - Release velocity anomalies and live OSV security advisory integration.
6. **Temporal Phantom Memory**:
   - Tracks previously unresolved dependencies.
   - Triggers an immediate `ALERT` if an unresolvable hallucinated package later appears on a registry (`NOT_FOUND` → `APPEARED`), neutralizing dependency confusion and pre-registration attacks.
7. **Contextual Repair & Mandatory Rescan Loop**:
   - Suggests verified replacements and standard-library modernizations.
   - Generates clean AST diff patches.
   - Enforces `PATCH -> RESCAN -> VERIFY`: a repair is never accepted unless the rescan validates all dependencies in the patched code.
8. **Decision Reconstruction & Append-Only Audit Trail**:
   - Answers: *"Why was package X blocked?"*
   - Reconstructs complete evidence snapshots: source code, canonical identity, registry response, trust signals, temporal history, and policy version.
9. **Developer Security Web Dashboard**:
   - Embedded single-page application dashboard featuring 10 views: Overview, Live Scan, Dependencies, Detail Dossier, Evidence Graph, Phantom Memory, Repair Center, Agent Firewall, Policy-as-Code, and Audit Logs.
10. **MCP Gateway**:
    - Exposes policy-gated Model Context Protocol tools (`verify_dependency`, `inspect_evidence`, `propose_repair`, `rescan_patch`) for AI agent integration.

---

## Quickstart

### 1. Installation

```bash
# Clone the repository
git clone <repo-url>
cd win_if_you_can

# Create and activate virtual environment
python -m venv .venv
# On Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
# On Linux/macOS:
source .venv/bin/activate

# Install in editable mode
pip install -e ".[dev]"
```

### 2. Running the Web Dashboard & REST API

```bash
uvicorn slopguard.api.app:app --host 0.0.0.0 --port 8000 --reload
```

Navigate to `http://localhost:8000` to open the security control plane dashboard.

### 3. Production Docker Setup

```bash
# Build and start with Docker Compose
docker-compose up --build -d

# Check service health
curl http://localhost:8000/api/v1/health
```

---

## CLI Usage

SLOPGUARD provides a production-grade CLI with Rich terminal output and CI-friendly `--json` mode:

```bash
# 1. Scan a source file, manifest, or entire directory
slopguard scan app.py
slopguard scan requirements.txt
slopguard scan . --profile strict_ci

# 2. Machine-readable JSON output for CI automation (exit code 2 on block)
slopguard scan . --json

# 3. Direct package verification against registry
slopguard verify requests
slopguard verify express --ecosystem npm

# 4. Inspect full evidence dossier (Registry, OSV Advisories, Provenance)
slopguard evidence requests

# 5. Inspect multi-dimensional release trust signals
slopguard trust requests

# 6. Query interactive Evidence Graph relationships
slopguard graph requests

# 7. Inspect Temporal Phantom Memory watchlist
slopguard phantom list

# 8. Decision reconstruction & audit trail
slopguard history requests

# 9. Propose candidate repairs and AST diff patch
slopguard repair cv2 --file app.py

# 10. Check or simulate Policy-as-Code profile
slopguard policy check --profile enterprise
```

---

## CI/CD Pipeline Integration

SLOPGUARD includes a standalone CI/CD gate script (`scripts/ci_check.py`) that integrates seamlessly into GitHub Actions, GitLab CI, Jenkins, and CircleCI:

```bash
python scripts/ci_check.py . --profile strict_ci --output-json slopguard-report.json
```

### Exit Codes:
- `0`: SUCCESS (All dependencies verified and allowed)
- `1`: PENDING REVIEW (Dependencies placed on `HOLD` under strict policy)
- `2`: GATE BLOCKED (Malicious, typosquatted, or hallucinated packages blocked)

A ready-to-use GitHub Actions workflow is provided at `.github/workflows/ci.yml`.

---

## Reproducible Benchmarks & Ablation Study

SLOPGUARD includes an empirical ablation benchmark measuring detection accuracy, extraction precision, and false-positive rates without fabricated numbers:

### Ablation Ladder:
- **B0**: Baseline regex extraction + naive HTTP 404 check (fails on aliases & comments).
- **B1**: AST extraction (eliminates comment false-positives, still lacks aliases).
- **B2**: AST + canonical alias resolution (correctly resolves `cv2` → `opencv-python`).
- **B3**: AST + aliases + trust engine (catches Cyrillic homoglyphs and typosquats).
- **B4**: AST + aliases + trust + temporal phantom memory (`NOT_FOUND` → `APPEARED`).
- **B5**: Full SLOPGUARD Control Plane (+ contextual repair & rescan gate).

To run the ablation ladder:
```bash
pytest -v tests/benchmark/test_ablation.py
```

---

## 90-Second Demonstration

Run the automated live demonstration script to witness the full control plane lifecycle:

```bash
python demo/scripts/run_90s_demo.py
```

Run individual failure injection scenarios from `demo/scenarios/`:
- `python demo/scenarios/scenario_a_missing_package.py` (Missing package → `BLOCK`)
- `python demo/scenarios/scenario_b_alias.py` (Alias resolution → `opencv-python`)
- `python demo/scenarios/scenario_c_verified.py` (Established package → `ALLOW`)
- `python demo/scenarios/scenario_d_registry_429.py` (429 Rate limit → `HOLD / REVIEW`)
- `python demo/scenarios/scenario_e_registry_timeout.py` (Timeout → `HOLD / REVIEW`)
- `python demo/scenarios/scenario_f_phantom_appeared.py` (Phantom appears → `ALERT`)

---

## Security Model & Limitations

- **Pre-Execution Boundary**: SLOPGUARD operates strictly prior to package installation or code execution. It never installs an unverified package to inspect it.
- **Fail-Safe Default**: Network failures default to quarantine (`HOLD`), never `NOT_FOUND`.
- **Deterministic Authority**: The LLM is restricted to explanation and repair generation. Final security decisions are enforced strictly by deterministic policy logic.
- **Known Limitations**:
  - Dynamic runtime imports constructed via string evaluation (e.g. `__import__(var)`) cannot be statically resolved by AST extraction and are flagged for review.
  - Private internal registries require configuring custom endpoint credentials in environment variables.

---

## Documentation Index

- [Architecture Specification](docs/architecture.md)
- [Threat Model](docs/threat-model.md)
- [API Reference](docs/api.md)
- [Developer Guide](docs/developer-guide.md)
- [Demonstration & Scenarios Guide](docs/demo.md)
- [Benchmark & Evaluation](docs/benchmark.md)
- [ADR 001: AST Extraction Over Regex](docs/adr/001-ast-over-regex.md)
- [ADR 002: Deterministic Policy Engine](docs/adr/002-deterministic-policy-engine.md)
- [ADR 003: LLM Explanations Without Verdict Authority](docs/adr/003-llm-not-final-verdict.md)
- [ADR 004: Temporal Phantom Memory](docs/adr/004-temporal-phantom-memory.md)
- [ADR 005: Distinction of Registry Outages](docs/adr/005-review-on-registry-failure.md)
- [ADR 006: Multi-Dimensional Release Trust Signals](docs/adr/006-multi-dimensional-trust.md)
- [ADR 007: Mandatory Rescan Gate on Repairs](docs/adr/007-mandatory-rescan-loop.md)
- [ADR 008: Policy-as-Code Configuration Profiles](docs/adr/008-policy-as-code-profiles.md)
- [ADR 009: Pre-Install Action Firewall](docs/adr/009-pre-install-action-firewall.md)
