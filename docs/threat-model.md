# SLOPGUARD Threat Model

## 1. Scope and Objective
SLOPGUARD protects software engineering environments, CI/CD pipelines, and autonomous AI coding agents from supply-chain attacks stemming from AI-generated code and automated package installations.

## 2. Threat Categories

### T1: AI Package Hallucination & Phantom Registration
- **Threat Vector**: An LLM invents a non-existent package name (e.g. `fastapi-pydantic-validator`, `huggingface-utils`). An attacker monitors hallucinated packages or scans public LLM prompts, registers the package on PyPI or npm with malicious payloads, and waits for AI agents or developers to install it.
- **SLOPGUARD Mitigation**:
  - Pre-install quarantine & identity verification.
  - Temporal Phantom Memory: First time a package is observed and not found, it is recorded. If it later appears (`NOT_FOUND -> APPEARED`), SLOPGUARD triggers a high-severity `ALERT` and blocks automatic installation.
  - Require human/security review for recently registered packages with no established reputation.

### T2: Typosquatting & Combative Naming
- **Threat Vector**: An LLM produces a slight typo or hallucinated variation of a popular package (e.g., `requets` instead of `requests`, `colorama-colors` instead of `colorama`), matching an attacker's uploaded package.
- **SLOPGUARD Mitigation**:
  - Distance metrics (Levenshtein, Jaro-Winkler, token-based, prefix/suffix stripping) against known popular packages.
  - Normalized candidate comparison.
  - Deterministic policy flags suspicious similarities as `Potential typosquat -> HOLD/BLOCK`.

### T3: Package Identity Confusion (Import vs Package Name)
- **Threat Vector**: Python import names often diverge from registry package names (e.g. `import cv2` -> `opencv-python`, `import yaml` -> `pyyaml`, `import PIL` -> `pillow`). Attackers register `cv2` or `yaml` on PyPI (or dependency confusion targets) to trap naive installers.
- **SLOPGUARD Mitigation**:
  - Standardized Identity Engine maintaining high-confidence mappings for known diverging aliases.
  - Distinguishes standard library imports from external dependencies.

### T4: Registry Outages & Network Degradation (Fail-Open Exploitation)
- **Threat Vector**: A network timeout, 429 rate limit, or 5xx outage causes a naive checker to report "not found" or fail open into allowing installation.
- **SLOPGUARD Mitigation**:
  - Network and registry errors are strictly isolated from `NOT_FOUND`.
  - Non-200 / timeout errors deterministically result in `REVIEW / HOLD`.
  - Default fail-safe posture: No dependency is allowed unless positive evidence of safety is validated.

### T5: Dependency Drift & TOCTOU (Time-of-Check to Time-of-Use)
- **Threat Vector**: A dependency is verified at version 1.0.0, but subsequent lockfile manipulation or wildcard version resolution installs version 1.1.0 which contains malicious release artifacts.
- **SLOPGUARD Mitigation**:
  - Exact version pinning and snapshot hashing.
  - Drift detection: Any delta between approved version and resolved lockfile release forces rescan.

### T6: Adversarial LLM Policy Bypass
- **Threat Vector**: An AI agent with tool execution rights attempts to persuade the control plane to whitelist a malicious package or ignores warnings.
- **SLOPGUARD Mitigation**:
  - Deterministic Policy Engine: Final gate verdicts (`ALLOW`, `HOLD`, `BLOCK`) are computed by deterministic Python code evaluating evidence tables, never by an LLM prompt response.
  - The LLM only generates repair explanations and rankings; it has zero authorization to alter policy verdicts.
