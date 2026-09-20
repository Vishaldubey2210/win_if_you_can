# SLOPGUARD — PyPI & TestPyPI Distribution and Publishing Guide

This guide details the exact steps for publishing **SLOPGUARD** (`slopguard-ai`) to TestPyPI and production PyPI using modern Python packaging standards and PyPI Trusted Publishing (OpenID Connect / OIDC).

---

## 1. Distribution Identity Reference

| Attribute | Value | Description |
|---|---|---|
| **PyPI Distribution Name** | `slopguard-ai` | Unique, non-colliding PyPI distribution package name. |
| **CLI Command** | `slopguard` | The command available in user shells after installation. |
| **Python Import Package** | `slopguard` | Module namespace: `import slopguard` |
| **Initial Version** | `0.1.0` | Semantic versioning release. |

---

## 2. Pre-Publish Verification Checklist

Before publishing, verify all local packaging criteria:

```bash
# 1. Clean previous build artifacts
rm -rf dist/ build/ *.egg-info

# 2. Build sdist and wheel
python -m build

# 3. Validate metadata and description rendering with Twine
twine check dist/*

# 4. Verify artifact outputs
# Expected:
#   dist/slopguard_ai-0.1.0-py3-none-any.whl
#   dist/slopguard_ai-0.1.0.tar.gz
```

---

## 3. TestPyPI Publishing & Verification

TestPyPI allows end-to-end testing of package registration, metadata rendering, and installation in an isolated sandbox.

### Step 3.1: Configure TestPyPI Account & API Token
1. Create an account at [test.pypi.org](https://test.pypi.org/).
2. Navigate to **Account Settings** -> **API Tokens** and generate a token with scope `Entire account` (or package-scoped if previously uploaded).
3. Securely set your API token in your shell environment:
   ```bash
   export TWINE_USERNAME="__token__"
   export TWINE_PASSWORD="pypi-test-token-value"
   # On Windows PowerShell:
   $env:TWINE_USERNAME="__token__"
   $env:TWINE_PASSWORD="pypi-test-token-value"
   ```

### Step 3.2: Upload Artifacts to TestPyPI
```bash
twine upload --repository-url https://test.pypi.org/legacy/ dist/*
```

### Step 3.3: Clean Environment Test from TestPyPI
Because TestPyPI does not mirror all public dependencies (like `fastapi`, `pydantic`, `httpx`), instruct pip to use the production PyPI index for dependencies:

```bash
# Create and activate an isolated test environment
python -m venv test_env
source test_env/bin/activate  # Or test_env\Scripts\activate on Windows

# Install slopguard-ai from TestPyPI with fallback to PyPI for dependencies
pip install --index-url https://test.pypi.org/simple/ \
            --extra-index-url https://pypi.org/simple/ \
            slopguard-ai

# Verify CLI entrypoint and commands
slopguard --version
slopguard --help
slopguard verify requests
```

---

## 4. Production PyPI Release (Trusted Publishing / OIDC)

SLOPGUARD uses **PyPI Trusted Publishing** via GitHub Actions OIDC. This eliminates long-lived static API tokens and prevents credential leaks.

### Step 4.1: Configure Trusted Publisher on PyPI
1. Log into your account at [pypi.org](https://pypi.org/).
2. Navigate to **Publishing** -> **Add a publisher**.
3. Select **GitHub**:
   - **Owner**: `Vishaldubey2210`
   - **Repository name**: `win_if_you_can`
   - **Workflow name**: `release.yml`
   - **Environment name**: `pypi`
   - **PyPI project name**: `slopguard-ai`

### Step 4.2: Trigger a Production Release
To trigger an automated release build and publish:
```bash
# 1. Ensure working tree is clean and all tests pass
pytest -v tests/

# 2. Create and push a signed semantic git tag
git tag -a v0.1.0 -m "Release v0.1.0: SLOPGUARD AI Dependency Control Plane"
git push origin v0.1.0
```

The GitHub Actions workflow (`.github/workflows/release.yml`) will:
1. Run the test suite (`pytest`)
2. Run self-scan security gate (`scripts/ci_check.py`)
3. Build the wheel and sdist (`python -m build`)
4. Validate package metadata (`twine check`)
5. Exchange a cryptographic OIDC token with PyPI and publish `slopguard-ai` to PyPI.

---

## 5. Post-Release Verification

Once published, any developer can install and use SLOPGUARD in seconds:

```bash
# Production installation
pip install slopguard-ai

# Smoke tests
slopguard --help
slopguard scan .
slopguard verify requests
slopguard trust fastapi
```
