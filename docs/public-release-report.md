# SLOPGUARD — Public PyPI Release Verification Report

---

## 1. Release Identity & Configuration

| Field | Value |
|---|---|
| **Project** | SLOPGUARD |
| **Distribution** | `slopguard-ai` |
| **CLI Executable** | `slopguard` |
| **Python Import** | `import slopguard` |
| **Version** | `0.1.0` |
| **GitHub Repository** | `Vishaldubey2210/win_if_you_can` |
| **Release Workflow** | `.github/workflows/release.yml` |
| **Deployment Environment** | `pypi` |

---

## 2. Release Verification Status

| Step / Verification | Status | Details |
|---|---|---|
| **Build** | **PASS** | `python -m build` generated `dist/slopguard_ai-0.1.0-py3-none-any.whl` (51.8 KB) and `dist/slopguard_ai-0.1.0.tar.gz` (58.4 KB). |
| **Twine Validation** | **PASS** | `twine check dist/*` verified both wheel and sdist with 0 errors/warnings. |
| **Full Test Suite** | **PASS (62/62)** | 62 passed in 77s across unit, integration, security red-team, ablation, and performance tests. |
| **Supply-Chain Self-Scan** | **PASS** | `python scripts/ci_check.py pyproject.toml --profile strict_ci` verified 13/13 runtime and dev dependencies compliant. |
| **Clean pip Install** | **PASS** | Wheel installed into isolated virtual environment (`.clean_test_env`) without accessing repository source tree. |
| **CLI Smoke Tests** | **PASS** | `slopguard --version` (0.1.0), `slopguard --help`, `slopguard verify requests`, and `slopguard scan` executed successfully. |
| **Source-Tree Leakage** | **PASS** | Confirmed `import slopguard` resolved strictly to `.clean_test_env/Lib/site-packages/slopguard/` with 0 local directory leakage. |
| **Security & Secrets Audit**| **PASS** | Verified 0 hardcoded tokens, 0 plaintext credentials, and least-privilege OIDC `id-token: write`. |
| **PyPI Name Availability** | **PASS** | Live query to `https://pypi.org/pypi/slopguard-ai/json` confirmed HTTP 404 (completely free and unallocated). |
| **TestPyPI Name Availability** | **PASS** | Live query to `https://test.pypi.org/pypi/slopguard-ai/json` confirmed HTTP 404 (completely free and unallocated). |
| **Trusted Publisher** | **AWAITING HUMAN ACTION** | Browser automated check confirmed PyPI requires active human user login / 2FA. |
| **Public PyPI** | **READY TO PUBLISH** | Artifacts, workflow, and tags prepared; awaiting Trusted Publisher registration on PyPI. |

---

## 3. Trusted Publisher Configuration (Exact Instructions)

To publish `slopguard-ai` directly from GitHub Actions without managing passwords or static tokens:

1. Log into your account at **[https://pypi.org/](https://pypi.org/)**.
2. Navigate to **Account Settings** -> **Publishing** -> **[Add a publisher](https://pypi.org/manage/account/publishing/)**.
3. Select **GitHub** and enter these exact values:
   - **PyPI Project Name**: `slopguard-ai`
   - **Owner**: `Vishaldubey2210`
   - **Repository name**: `win_if_you_can`
   - **Workflow name**: `release.yml`
   - **Environment name**: `pypi`
4. Click **Add**.

---

## 4. Triggering the Release

Once the Trusted Publisher is added on PyPI, trigger the automated publication by creating and pushing the release tag:

```bash
git tag -a v0.1.0 -m "Release v0.1.0: SLOPGUARD AI Dependency Control Plane"
git push origin v0.1.0
```

The GitHub Actions workflow (`.github/workflows/release.yml`) will automatically run tests, self-scan, build artifacts, validate metadata, and publish `slopguard-ai` to PyPI via OIDC.
