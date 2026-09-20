# SLOPGUARD — Public PyPI Release Verification Report

---

## 1. Release Identity & Live Registry Coordinates

| Field | Value |
|---|---|
| **Project** | SLOPGUARD |
| **Distribution Package** | `slopguard-ai` |
| **Live PyPI URL** | [https://pypi.org/project/slopguard-ai/0.1.0/](https://pypi.org/project/slopguard-ai/0.1.0/) |
| **CLI Executable** | `slopguard` |
| **Python Import Namespace** | `import slopguard` |
| **Published Version** | `0.1.0` |
| **GitHub Repository** | [Vishaldubey2210/win_if_you_can](https://github.com/Vishaldubey2210/win_if_you_can) |
| **Release Workflow Run** | [Run #35497320179](https://github.com/Vishaldubey2210/win_if_you_can/actions/runs/35497320179) (Success) |
| **Publishing Mechanism** | PyPI Trusted Publishing (OpenID Connect / OIDC) |

---

## 2. Release Verification Status

| Step / Verification | Status | Details |
|---|---|---|
| **Build** | **PASS** | `python -m build` generated `dist/slopguard_ai-0.1.0-py3-none-any.whl` (51.8 KB) and `dist/slopguard_ai-0.1.0.tar.gz` (58.4 KB). |
| **Twine Validation** | **PASS** | `twine check dist/*` verified both wheel and sdist with 0 errors/warnings. |
| **Full Test Suite** | **PASS (62/62)** | 62 passed in GitHub Actions CI (Ubuntu, Python 3.11) across unit, integration, security red-team, ablation, and performance tests. |
| **Supply-Chain Self-Scan** | **PASS** | `python scripts/ci_check.py pyproject.toml --profile strict_ci` verified 13/13 runtime and dev dependencies compliant. |
| **Trusted Publisher** | **CONFIGURED & VERIFIED** | Registered on PyPI for `Vishaldubey2210/win_if_you_can` under environment `pypi`. |
| **Public PyPI** | **PUBLISHED** | Successfully published to official PyPI index via GitHub Actions OIDC. |
| **Clean pip Install** | **PASS** | Successfully installed via `pip install slopguard-ai` from live PyPI into fresh isolated virtual environment. |
| **CLI Smoke Tests** | **PASS** | `slopguard --version` (0.1.0), `slopguard --help`, `slopguard verify requests`, and `slopguard scan` executed successfully from live package. |
| **Source-Tree Leakage** | **PASS** | Confirmed `import slopguard` resolved strictly to `site-packages/slopguard/` with 0 local directory leakage. |
| **Security & Secrets Audit**| **PASS** | Verified 0 hardcoded tokens, 0 plaintext credentials, and least-privilege OIDC `id-token: write`. |
| **Remaining Manual Actions**| **NONE** | Package is live, publicly installable, and fully operational. |

---

## 3. Installation Experience Verification

Any developer worldwide can now install and execute SLOPGUARD:

```bash
# 1. Install from official PyPI
pip install slopguard-ai

# 2. Check installed version
slopguard --version
# Output: slopguard, version 0.1.0

# 3. Direct verification of external packages
slopguard verify requests
# Output: FOUND, 163 releases, verified GitHub repository

# 4. Scan application code or manifests
slopguard scan app.py
```
