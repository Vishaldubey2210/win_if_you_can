# SLOPGUARD Developer Guide

This guide covers local development workflows, extending adapters and rules, running benchmarks, and contributing to the **SLOPGUARD AI Dependency Control Plane**.

---

## 1. Development Environment Setup

### Prerequisites
- Python 3.10+ (tested on Python 3.11, 3.12, 3.14)
- `pip` or modern virtual environment manager
- Git

### Initializing Environment

```bash
# Clone the repository
git clone https://github.com/your-org/slopguard.git
cd slopguard

# Create and activate virtual environment
python -m venv .venv
# On Linux/macOS:
source .venv/bin/activate
# On Windows (PowerShell):
.\.venv\Scripts\Activate.ps1

# Install in editable development mode with testing dependencies
pip install -e ".[dev]"
```

---

## 2. Running Test Suites

SLOPGUARD enforces comprehensive test coverage across unit logic, security failure injection, adversarial confusable attacks, and end-to-end integration:

```bash
# Run entire test suite
pytest -v

# Run only unit tests
pytest -v tests/unit/

# Run security and failure injection tests
pytest -v tests/security/

# Run API integration tests
pytest -v tests/integration/

# Run ablation ladder benchmark
pytest -v tests/benchmark/test_ablation.py
```

---

## 3. Core Architectural Principles

When writing or reviewing code, adhere strictly to the non-negotiable engineering principles:

1. **Existence != Trust != Future Safety**: Merely resolving a package on PyPI or npm does not indicate that it is safe or trustworthy.
2. **Never Convert Network/Registry Failures to `NOT_FOUND`**:
   - HTTP 429 -> `HOLD / REVIEW`
   - HTTP 5xx -> `HOLD / REVIEW`
   - Network Timeout -> `HOLD / REVIEW`
   - Only authoritative HTTP 404 from the registry can indicate `NOT_FOUND`.
3. **Deterministic Gate Enforcements**: The gate action (`ALLOW`, `HOLD`, `BLOCK`, `ALERT`) is decided by deterministic policy-as-code rules, never probabilistic LLM reasoning.
4. **Mandatory Rescan Loop**: When proposing a dependency fix or repair, the engine enforces:
   `PATCH -> RESCAN -> VERIFY`
   A patch is rejected unless the rescan verifies all dependencies in the modified code.

---

## 4. Extending SLOPGUARD

### Adding a New Identity Mapping
Add canonical alias mappings in `slopguard/identity/resolver.py` under `PYPI_IMPORT_TO_PACKAGE` or `NPM_IMPORT_TO_PACKAGE`:
```python
PYPI_IMPORT_TO_PACKAGE = {
    "cv2": "opencv-python",
    "PIL": "pillow",
    "yaml": "pyyaml",
    "your_alias": "canonical-package-name",
}
```

### Adding a New Policy Rule or Profile
Configurable policy profiles are managed in `slopguard/policy/config.py`:
- `PolicyProfileName.DEVELOPMENT`: Relaxed for local prototyping.
- `PolicyProfileName.STRICT_CI`: Zero-tolerance quarantine gate for CI/CD pipelines.
- `PolicyProfileName.ENTERPRISE`: Strict provenance and release age enforcement.

To customize rules programmatically:
```python
from slopguard.policy.config import PolicyConfig, PolicyAction

config = PolicyConfig(
    missing_package_action=PolicyAction.BLOCK,
    registry_timeout_action=PolicyAction.HOLD,
    weak_provenance_action=PolicyAction.HOLD,
)
```

### Adding an MCP Tool
Expose tools to agent frameworks via `slopguard/mcp/gateway.py`. All MCP tool executions must pass through the `ScannerService` or `DeterministicPolicyEngine` to guarantee policy gate enforcement.

---

## 5. Running the Local API and Web Dashboard

Launch the FastAPI backend and embedded developer security dashboard:

```bash
uvicorn slopguard.api.app:app --reload --port 8000
```

Open your browser at `http://localhost:8000` to access the production-grade control plane dashboard.
