# SLOPGUARD
### AI Dependency Control Plane & Supply-Chain Firewall

> **Verify identity • Score trust • Remember phantoms • Repair safely • Gate installation**

[![PyPI Version](https://img.shields.io/pypi/v/slopguard-ai.svg)](https://pypi.org/project/slopguard-ai/#description)
[![VS Code Marketplace](https://img.shields.io/badge/VS_Code_Marketplace-v0.1.2-blue.svg)](https://marketplace.visualstudio.com/items?itemName=vishaldubey2210.slopguard)
[![Python Version](https://img.shields.io/pypi/pyversions/slopguard-ai.svg)](https://pypi.org/project/slopguard-ai/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-58%20unit%20%2B%2030%20extension%20passed-brightgreen.svg)](tests/)

---

## Project Links

- **GitHub Repository**: [https://github.com/Vishaldubey2210/win_if_you_can](https://github.com/Vishaldubey2210/win_if_you_can)
- **PyPI Package (`slopguard-ai`)**: [https://pypi.org/project/slopguard-ai/#description](https://pypi.org/project/slopguard-ai/#description)
- **VS Code Marketplace (`vishaldubey2210.slopguard`)**: [https://marketplace.visualstudio.com/items?itemName=vishaldubey2210.slopguard](https://marketplace.visualstudio.com/items?itemName=vishaldubey2210.slopguard)
- **Model Context Protocol (MCP) Guide**: [docs/mcp-server-guide.md](docs/mcp-server-guide.md)

---

## Table of Contents

1. [The Problem](#1-the-problem)
2. [Threat Model](#2-threat-model)
3. [Core Principle](#3-core-principle)
4. [Solution](#4-solution)
5. [Architecture](#5-architecture)
6. [The Nine-Stage Pipeline](#6-the-nine-stage-pipeline)
7. [Identity Graph](#7-identity-graph)
8. [Evidence Graph](#8-evidence-graph)
9. [Trust Engine](#9-trust-engine)
10. [Temporal Phantom Memory](#10-temporal-phantom-memory)
11. [Contextual Repair Loop](#11-contextual-repair-loop)
12. [Policy-as-Code & Profiles](#12-policy-as-code--profiles)
13. [VS Code Extension](#13-vs-code-extension)
14. [Model Context Protocol (MCP) Server](#14-model-context-protocol-mcp-server)
15. [CLI Reference](#15-cli-reference)
16. [Web Dashboard](#16-web-dashboard)
17. [Failure-Safe Design](#17-failure-safe-design)
18. [Benchmark & Evaluation](#18-benchmark--evaluation)
19. [Security Model & Limitations](#19-security-model--limitations)
20. [Repository Structure](#20-repository-structure)
21. [Testing & Verification](#21-testing--verification)
22. [Installation & Quickstart](#22-installation--quickstart)
23. [License](#23-license)

---

## 1. The Problem

Modern AI coding agents (Claude, Copilot, Cursor, Devin, Windsurf) frequently hallucinate non-existent package dependencies or confuse internal module imports with external distribution specifiers.

Attackers exploit this through **Phantom Dependency Hijacking** and **Pre-Registration Attacks**:
1. An LLM suggests a convincing but non-existent package (e.g. `langchain-hyper-fast-auth` or typosquat `requets`).
2. Attackers continuously scrape public AI prompts, repositories, and benchmark datasets for unresolvable packages.
3. The attacker registers the hallucinated name on PyPI or npm with malicious pre-install hooks (`setup.py` / `install.js`).
4. When the developer or automated AI agent runs `pip install` or `npm install`, the malicious code executes with full local privileges, leading to Remote Code Execution (RCE) and credential theft.

Traditional Software Composition Analysis (SCA) runs *after* installation in CI/CD, which is fatally too late.

---

## 2. Threat Model

| Threat Vector | Attack Surface | Impact | Mitigation in SLOPGUARD |
| :--- | :--- | :--- | :--- |
| **Phantom Hallucinations** | AI code generation / imports | RCE via pre-registration | Pre-install registry check + temporal memory |
| **Typosquatting** | Lookalike package names | Malware execution | Damerau-Levenshtein distance + popularity analysis |
| **Unicode Confusables** | Homoglyphs (Cyrillic `а` vs Latin `a`) | Package impersonation | Unicode confusable skeleton matching |
| **Dependency Confusion** | Internal module vs Public PyPI | Organization asset compromise | PEP 503 normalization + stdlib/internal resolution |
| **Transient Registry Outage**| Network drop / HTTP 429 / 503 | False positive blockage | Fails safe to `HOLD / REVIEW`; never `NOT_FOUND` |
| **Silent Repair Exploitation**| Patching without rescan | Introducing fresh vulnerabilities | Mandatory `PATCH -> RESCAN -> VERIFY` validation gate |

---

## 3. Core Principle

```
EXISTENCE != TRUST != FUTURE SAFETY
```

- **Existence**: Just because a package exists on PyPI does NOT mean it is safe.
- **Trust**: Verified release counts, repository provenance, maintainer history, and vulnerability advisories determine trust.
- **Future Safety**: A package that was missing yesterday and appeared today is an anomaly (`APPEARED`), not automatically safe.

---

## 4. Solution

**SLOPGUARD** (`slopguard-ai`) is an enterprise-grade, pre-install AI Dependency Control Plane and Supply-Chain Firewall. It intercepts dependency definitions in real time, computes multi-dimensional trust scores, tracks historical observations, suggests verified repairs, and enforces deterministic Policy-as-Code gates (`ALLOW`, `HOLD`, `BLOCK`, `ALERT`) before package code can ever execute.

---

## 5. Architecture

```mermaid
flowchart TD
    subgraph ClientLayer ["Client / Presentation Layer"]
        IDE["VS Code Extension<br/>(Diagnostics / QuickFix / Watcher)"]
        CLI["SLOPGUARD CLI<br/>(Terminal / CI Runner)"]
        MCP["MCP Server<br/>(Cursor / Claude / AI Agents)"]
    end

    subgraph CoreEngine ["SLOPGUARD Control Plane (Python Core)"]
        direction TB
        E1["1. EXTRACT<br/>AST & Manifest Parsers"] --> E2["2. IDENTITY<br/>PEP 503 Normalizer & Alias Graph"]
        E2 --> E3["3. VERIFY<br/>PyPI & npm Registry Adapters"]
        E3 --> E4["4. EVIDENCE<br/>OSV Advisories & Provenance"]
        E4 --> E5["5. TRUST<br/>Velocity & Confusable Detector"]
        E5 --> E6["6. MEMORY<br/>Temporal Phantom Watchlist"]
        E6 --> E7["7. REPAIR<br/>Contextual AST Diff Engine"]
        E7 --> E8["8. RESCAN<br/>Mandatory Validation Loop"]
        E8 --> E9["9. POLICY GATE<br/>Deterministic Policy-as-Code"]
    end

    subgraph Verdicts ["Verdicts & Policy Gates"]
        ALLOW["ALLOW (Verified Safe)"]
        HOLD["HOLD (Review Required)"]
        BLOCK["BLOCK (Quarantined)"]
        ALERT["ALERT (Temporal Anomaly)"]
    end

    ClientLayer --> CoreEngine
    E9 --> ALLOW
    E9 --> HOLD
    E9 --> BLOCK
    E9 --> ALERT
```

---

## 6. The Nine-Stage Pipeline

```mermaid
sequenceDiagram
    participant Dev as Developer / AI Agent
    participant Ext as SLOPGUARD Extractor
    participant Reg as Registry & OSV
    participant Memory as Phantom Memory
    participant Gate as Policy Engine

    Dev->>Ext: Code / Manifest (e.g. import requets)
    Ext->>Reg: Verify package metadata & advisories
    Reg-->>Ext: Registry status (NOT_FOUND / FOUND)
    Ext->>Memory: Check temporal observation history
    Memory-->>Ext: State transition (NOT_FOUND -> WATCH)
    Ext->>Gate: Evaluate Trust & Policy Rules
    Gate-->>Dev: Verdict: BLOCK (Risk: HIGH, Suggested: requests)
```

1. **EXTRACT**: AST-first parser for Python, JS/TS, and manifests (`requirements.txt`, `pyproject.toml`, `package.json`).
2. **IDENTITY**: Canonical mapping (e.g., `import cv2` -> `opencv-python`, `yaml` -> `PyYAML`).
3. **VERIFY**: Failure-isolated registry adapters ensuring HTTP 429/timeout never becomes a false `NOT_FOUND`.
4. **EVIDENCE**: Live Open Source Vulnerability (OSV) query, repository links, cryptographic provenance.
5. **TRUST**: Release velocity, account age, Damerau-Levenshtein typosquat distance, and homoglyph skeletons.
6. **MEMORY**: Temporal tracking of unresolvable packages (`NOT_FOUND` -> `WATCH` -> `APPEARED`).
7. **REPAIR**: Contextual AST patch synthesis with candidate confidence scoring.
8. **RESCAN**: Mandatory verification loop: generated patches must be rescanned before approval.
9. **POLICY GATE**: Configurable profiles (`DEVELOPMENT`, `STRICT_CI`, `ENTERPRISE`) enforcing deterministic verdicts.

---

## 7. Identity Graph

```mermaid
graph LR
    subgraph Imports ["Import Specifiers"]
        I1["import cv2"]
        I2["import PIL"]
        I3["import yaml"]
        I4["import sklearn"]
    end

    subgraph Canonical ["Canonical Distributions"]
        C1["opencv-python"]
        C2["Pillow"]
        C3["PyYAML"]
        C4["scikit-learn"]
    end

    I1 -->|Alias 0.99| C1
    I2 -->|Alias 0.99| C2
    I3 -->|Alias 0.99| C3
    I4 -->|Alias 0.99| C4
```

---

## 8. Evidence Graph

```mermaid
graph TD
    PKG["Package: requests"]
    VER["Release: 2.34.2"]
    REPO["Repository: github.com/psf/requests"]
    OSV["OSV: 0 Active Vulnerabilities"]
    PROV["Provenance: Attested Build"]

    PKG -->|HAS_RELEASE| VER
    PKG -->|HOSTED_AT| REPO
    PKG -->|AFFECTED_BY| OSV
    PKG -->|ATTESTED_BY| PROV
```

---

## 9. Trust Engine

The trust engine evaluates five independent dimensions:
1. **Identity Trust**: Canonical resolution score and alias confidence.
2. **Registry Trust**: Total release count ($\ge 3$), latest version age, and active registry status.
3. **Vulnerability Trust**: CVSS severity score from Google OSV (Critical/High triggers `BLOCK`).
4. **Adversarial Trust**: Typosquat distance to top-10,000 packages and Unicode homoglyphs.
5. **Provenance Trust**: Verified source repository linkage and build attestations.

---

## 10. Temporal Phantom Memory

```mermaid
stateDiagram-v2
    [*] --> NOT_FOUND: First unresolvable import observed
    NOT_FOUND --> WATCH: Monitored in temporal watchlist
    WATCH --> APPEARED: Package registered on registry (ALERT!)
    WATCH --> RESOLVED: Verified alternative adopted
    APPEARED --> QUARANTINE: Strict gate review required
```

---

## 11. Contextual Repair Loop

```mermaid
flowchart LR
    Bug["Buggy Import<br/>import requets"] --> Repair["Repair Engine<br/>Candidate: requests (95%)"]
    Repair --> Patch["Generate Unified Diff"]
    Patch --> Rescan["Mandatory Rescan Gate"]
    Rescan -->|PASS| Apply["Apply Safe Patch"]
    Rescan -->|FAIL| Reject["Reject Unsafe Fix"]
```

---

## 12. Policy-as-Code & Profiles

| Rule Condition | DEVELOPMENT | STRICT_CI (Default) | ENTERPRISE |
| :--- | :---: | :---: | :---: |
| Package not found (HTTP 404) | `BLOCK` | `BLOCK` | `BLOCK` |
| Typosquatting detected | `BLOCK` | `BLOCK` | `BLOCK` |
| Critical OSV advisory ($\text{CVSS} \ge 9.0$) | `BLOCK` | `BLOCK` | `BLOCK` |
| High OSV advisory ($\text{CVSS} \ge 7.0$) | `HOLD` | `BLOCK` | `BLOCK` |
| Registry failure (timeout / 429) | `HOLD` | `HOLD` | `BLOCK` |
| Package age < 30 days | `ALLOW` | `HOLD` | `BLOCK` |
| Phantom state `APPEARED` | `ALERT` | `ALERT` | `BLOCK` |

---

## 13. VS Code Extension

Install from VS Code Marketplace: **[`vishaldubey2210.slopguard`](https://marketplace.visualstudio.com/items?itemName=vishaldubey2210.slopguard)**.

```mermaid
flowchart TD
    Open["Open / Save File (test.py)"] --> Watcher["Watcher & Scan Coordinator"]
    Watcher --> Engine{"Engine Ready?"}
    Engine -->|Yes| Scan["Execute Scan (REST / CLI)"]
    Engine -->|No| Queue["Queue & Buffer Scan Request"]
    Queue -->|Ready Fired| Flush["Flush & Execute Deduplicated Queue"]
    Scan --> Diag["Publish SLOPGUARD Diagnostics"]
    Diag --> QuickFix["1-Click Quick Fix CodeAction"]
    QuickFix --> Rescan["Mandatory Rescan"]
    Rescan --> Clean["Clean Results (Diagnostic Disappears)"]
```

### Features:
- **Robust CLI Auto-Discovery**: 7-tier search resolving Python user scripts and virtualenvs.
- **Inline Diagnostics**: High-visibility squigglies displaying Registry, Risk, and Suggested fix.
- **Quick Fixes**: One-click replacement of typosquats with verified packages.
- **Non-Blocking Architecture**: Background scan queue with zero editor freezing.

---

## 14. Model Context Protocol (MCP) Server

SLOPGUARD provides full **MCP Server** support for Cursor, Claude Desktop, Antigravity, and AI Agents over `stdio` and `sse` transports.

### Exposed Tools:
- `verify_dependency`: Checks package existence, canonical identity, release count, and gate verdicts.
- `scan_code`: Evaluates full code snippets or manifests before saving or running.
- `inspect_evidence`: Retrieves live OSV vulnerabilities, repository URLs, and registry metadata.
- `inspect_history`: Inspects temporal phantom memory observations and state transitions.
- `propose_repair`: Generates verified replacement packages and AST unified diffs.
- `rescan_patch`: Enforces mandatory rescan gate on proposed patches.
- `gate_install`: Checks agent installation permits before running package managers.

### Quick Connect:
Add to `.cursor/mcp.json` or `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "slopguard": {
      "command": "slopguard",
      "args": ["mcp", "run", "--transport", "stdio"]
    }
  }
}
```

---

## 15. CLI Reference

```bash
# Verify single package
slopguard verify requests

# Scan code file or directory
slopguard scan app.py --profile strict_ci

# Run contextual repair
slopguard repair cv2 --file app.py

# Rescan patched file through mandatory verification gate
slopguard rescan app.py

# Start MCP Server
slopguard mcp run --transport stdio

# Generate MCP Client Configurations (Claude / Cursor)
slopguard mcp config

# Start REST API daemon and Web Dashboard
slopguard serve --port 8000
```

---

## 16. Failure-Safe Design

> **Crucial Guarantee**: Registry downtime, network timeouts, DNS failures, or HTTP 429 rate limits are **NEVER** classified as `NOT_FOUND`.

If a registry fails to respond:
1. The adapter flags the status as `TIMEOUT`, `RATE_LIMITED`, or `SERVER_ERROR`.
2. The policy engine triggers `HOLD / REVIEW`.
3. The cache prevents caching transient network failures as negative hits.

---

## 17. Benchmark & Evaluation

Evaluated on the frozen benchmark corpus across 4 standardized categories:

| Category | Samples | Status | Primary Enforcement |
| :--- | :---: | :---: | :--- |
| **REAL** (requests, fastapi, pydantic) | 4 | **PASS** | Validated multi-release histories |
| **PHANTOM** (langchain-hyper-fast-auth) | 3 | **PASS** | Blocked 404 + Temporal tracking |
| **TRICKY** (cv2, PIL, yaml, sklearn) | 4 | **PASS** | Canonical identity mapping |
| **ADVERSARIAL** (requets, homoglyphs) | 2 | **PASS** | Typosquat distance & confusable skeleton |

---

## 18. Security Model & Limitations

- **Source of Truth**: The Python core (`slopguard-ai`) is the sole authority for security decisions; the VS Code extension acts purely as a client.
- **Limitations**:
  - SLOPGUARD cannot guarantee future security of legitimately published packages that suffer post-install account takeovers.
  - Provable protection requires enforcing the `RESCAN` gate on all code patches.
  - Pre-install scanning requires AST-parseable imports or manifest files.

---

## 19. Repository Structure

```
win_if_you_can/
├── slopguard/               # Python Core Engine (Source of Truth)
│   ├── api/                 # FastAPI REST Engine & Static Web Dashboard
│   ├── audit/               # Forensic Audit Trail & Decision Reconstruction
│   ├── cli/                 # Click-based CLI Commands & Rich Terminal Output
│   ├── core/                # ScannerService & Pydantic Domain Models
│   ├── evidence/            # Evidence Graph & Provenance Extractors
│   ├── extraction/          # AST Extractors (Python, JS/TS, Manifests)
│   ├── identity/            # PEP 503 Normalizer & Alias Graph
│   ├── mcp/                 # Model Context Protocol (MCP) Server & Gateway
│   ├── memory/              # Temporal Phantom Watchlist & Transitions
│   ├── policy/              # Deterministic Policy-as-Code Engine
│   ├── registry/            # PyPI, npm, and OSV Registry Adapters
│   ├── repair/              # Contextual Candidate Generator & AST Patcher
│   └── trust/               # Multi-Dimensional Trust & Typosquat Evaluator
├── vscode-extension/        # VS Code Marketplace Extension
│   ├── src/                 # TypeScript Services, Providers, and Commands
│   ├── media/               # Icons and UI Assets
│   └── package.json         # Extension Manifest
├── tests/                   # Complete Unit, Security, & Integration Test Suite
├── docs/                    # Architecture Specifications & Audit Reports
└── pyproject.toml           # Python Package Build Configuration
```

---

## 20. Testing & Verification

Run the test suite across components:

```bash
# 1. Run Python Core Unit Tests (58 tests)
pytest tests/unit/ -v

# 2. Run VS Code Extension Automated Tests (30 tests)
cd vscode-extension
npm test

# 3. Run Real-World Acceptance Pipeline
node scripts/acceptance_test.js
```

---

## 21. Installation & Quickstart

```bash
# 1. Install from PyPI
pip install slopguard-ai

# 2. Verify installation
slopguard --version

# 3. Scan a file
slopguard scan test.py
```

---

## 22. License

SLOPGUARD is licensed under the [Apache License, Version 2.0](LICENSE).
