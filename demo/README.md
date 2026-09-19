# SLOPGUARD Demo Harness & Scenarios

This directory contains deterministic, reproducible demonstration scenarios and the 90-second end-to-end demo script for the **SLOPGUARD AI Dependency Control Plane**.

---

## 1. Directory Structure

```
demo/
├── README.md                          # Harness documentation
├── fixtures/
│   └── offline_responses.json         # Deterministic offline registry fixtures
├── sample_projects/
│   └── ai_generated_app.py            # AI-generated code with phantoms and aliases
├── scenarios/
│   ├── scenario_a_missing_package.py  # Missing package -> BLOCK
│   ├── scenario_b_alias.py            # Import alias -> Resolve & Verify
│   ├── scenario_c_verified.py         # Known verified package -> ALLOW
│   ├── scenario_d_registry_429.py     # Registry 429 rate limit -> HOLD / REVIEW
│   ├── scenario_e_registry_timeout.py # Registry timeout -> HOLD / REVIEW
│   └── scenario_f_phantom_appeared.py # Phantom appears later -> ALERT
└── scripts/
    └── run_90s_demo.py                # Complete 90-second CLI demonstration
```

---

## 2. Running the 90-Second End-to-End Demo

Execute the standalone demonstration script:

```bash
python demo/scripts/run_90s_demo.py
```

### What this demonstrates:
1. **Source Extraction**: AST parser detects all imports in untrusted AI code.
2. **Identity Resolution**: Maps `cv2` -> `opencv-python` with canonical PEP 503 normalization.
3. **Quarantine Gate**: Blocks hallucinated package `langchain_hyper_fast_auth_v2` with HTTP 404 registry evidence.
4. **Evidence Dossier**: Displays verified release count, repository link, and OSV advisories.
5. **Contextual Repair**: Proposes AST diff patch replacing `cv2` with `opencv-python`.
6. **Mandatory Rescan Loop**: Runs `PATCH -> RESCAN -> VERIFY` gate check.
7. **Failure Injection (429 Outage)**: Enforces fail-safe `HOLD / REVIEW` rather than converting network errors to `NOT_FOUND`.
8. **Decision Reconstruction**: Deterministic audit response explaining why the package was blocked.

---

## 3. Running Individual Scenarios

Run any scenario independently:

```bash
python demo/scenarios/scenario_a_missing_package.py
python demo/scenarios/scenario_b_alias.py
python demo/scenarios/scenario_c_verified.py
python demo/scenarios/scenario_d_registry_429.py
python demo/scenarios/scenario_e_registry_timeout.py
python demo/scenarios/scenario_f_phantom_appeared.py
```
