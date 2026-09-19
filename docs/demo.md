# SLOPGUARD Live Demonstration & Scenario Guide

This document describes how to execute and reproduce the demonstration scenarios for the **SLOPGUARD AI Dependency Control Plane**.

---

## 1. 90-Second Control Plane Demonstration

Run the automated CLI demo script:

```bash
python demo/scripts/run_90s_demo.py
```

### Demonstration Walkthrough:
1. **Source Extraction**: AST parser inspects untrusted AI code.
2. **Canonical Identity**: Automatically resolves `cv2` -> `opencv-python` with PEP 503 normalization.
3. **Quarantine Gate**: Intercepts hallucinated `langchain_hyper_fast_auth_v2` with HTTP 404 registry evidence, issuing a `BLOCK` verdict.
4. **Evidence Dossier**: Queries live PyPI metadata, repository URLs, release counts, and OSV security advisories for `requests`.
5. **Contextual Repair Engine**: Generates replacement proposals and clean AST diff patches.
6. **Mandatory Rescan Loop**: Enforces `PATCH -> RESCAN -> VERIFY`.
7. **Failure Injection**: Injects an HTTP 429 rate limit error to demonstrate fail-safe `HOLD / REVIEW` posture (no false `NOT_FOUND` conversions).
8. **Decision Reconstruction**: Deterministic audit query explaining why a specific package was blocked.

---

## 2. Deterministic Failure Injection Scenarios

Individual scenarios can be tested independently from `demo/scenarios/`:

| Scenario File | Target Case | Injected Condition | Enforced Policy Action |
|---|---|---|---|
| `scenario_a_missing_package.py` | `langchain-hyper-fast-auth-helper-v9` | HTTP 404 from PyPI | `BLOCK` |
| `scenario_b_alias.py` | `cv2` | Import alias -> `opencv-python` | `ALLOW` / `RESOLVED` |
| `scenario_c_verified.py` | `fastapi` | High release count + repository | `ALLOW` |
| `scenario_d_registry_429.py` | `throttled-lib` | Injected HTTP 429 | `HOLD` (Human Review) |
| `scenario_e_registry_timeout.py` | `unresponsive-pkg` | Injected Network Timeout | `HOLD` (Human Review) |
| `scenario_f_phantom_appeared.py` | `target-phantom-corp` | Transition `NOT_FOUND` -> `APPEARED` | `ALERT` (Quarantine) |

### Executing Scenarios:
```bash
python demo/scenarios/scenario_a_missing_package.py
python demo/scenarios/scenario_b_alias.py
python demo/scenarios/scenario_c_verified.py
python demo/scenarios/scenario_d_registry_429.py
python demo/scenarios/scenario_e_registry_timeout.py
python demo/scenarios/scenario_f_phantom_appeared.py
```
