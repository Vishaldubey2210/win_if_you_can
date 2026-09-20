# SLOPGUARD — AI Dependency Firewall for VS Code

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python Package](https://img.shields.io/pypi/v/slopguard-ai.svg)](https://pypi.org/project/slopguard-ai/)
[![VS Code Extension](https://img.shields.io/badge/VS_Code-v0.1.0-brightgreen.svg)]()

> **The Pre-Install AI Dependency Control Plane & Supply-Chain Firewall for VS Code.**
> Sits directly between AI coding agents (Copilot, Cursor, Claude Code, Gemini Code Assist, Windsurf) and package registries to prevent dependency hallucination, typosquatting attacks, and unverified package execution.

---

## 🏛 Architecture

The SLOPGUARD VS Code extension is an **ergonomic Developer Experience (DX) and client layer**. It does **not** duplicate or rebuild security logic inside TypeScript.

```
      VS CODE EXTENSION (Client / Presentation / DX Layer)
           │
           ├─► Inline Diagnostics (Squigglies & Hover Tooltips)
           ├─► Activity Bar TreeView (Dependencies & Phantoms)
           ├─► Quick Fixes (1-Click Propose & Replace)
           ├─► Webview Panel (Evidence Dossier & Evidence Graph)
           └─► Status Bar Indicator (🛡 Live Metrics)
                   │
                   ▼ (REST API: localhost:8000 or CLI fallback)
      SLOPGUARD CORE ENGINE (Python Package: slopguard-ai)
           │
     EXTRACT ──► IDENTITY ──► VERIFY ──► EVIDENCE ──► TRUST ──► MEMORY ──► POLICY GATE
                                                                             │
                                                                   ALLOW / HOLD / BLOCK
```

---

## ⚡ Prerequisites

To use SLOPGUARD in VS Code, install the official SLOPGUARD Python package:

```bash
pip install slopguard-ai
```

Optionally launch the local daemon for millisecond-latency cached evaluations:
```bash
slopguard serve
# Started server at http://127.0.0.1:8000
```
*(If the local daemon is not running, the extension automatically falls back to invoking the `slopguard` CLI).*

---

## 🌟 Key Features

### 1. Inline Diagnostics & Squigglies
- **`BLOCK`**: Highlighted in red (`Error`) when an imported package cannot be verified on registries or poses high typosquatting risk.
- **`HOLD` / `ALERT`**: Highlighted in yellow (`Warning`) when evidence is incomplete or when an unverified phantom package suddenly appears.
- **`ALLOW`**: Displays blue informational hints when imports resolve to known canonical packages (e.g., `import cv2` resolves to `opencv-python`).

### 2. Activity Bar Sidebar
- **Dependency Control Plane**: Real-time breakdown of:
  - 🛡 Workspace Overview & Total Evaluated Packages
  - 🚫 Blocked Dependencies
  - ⚠️ Review Required
  - ✅ Verified Safe
- **Temporal Phantom Watchlist**: Tracks dependencies that failed identity verification over time, showing first/last seen timestamps, observation counts, and alerting on `APPEARED` state changes.

### 3. Quick Fixes & Repair Center
- One-click Code Action to replace typosquatted or unverified dependencies with canonical alternatives suggested by the SLOPGUARD Repair Engine.
- **Rescan Guarantee**: Applying a repair automatically triggers an immediate rescan. A repair is never assumed safe until the backend policy gate validates it.

### 4. Interactive Evidence Dossier & Graph
- Inspect the complete cryptographic & factual trail for any package:
  - **Registry Metadata**: Official existence, release counts, latest version.
  - **Repository & Provenance**: GitHub/GitLab origin, star count, license.
  - **Advisory History**: Live vulnerability queries via OSV.
  - **Evidence Graph**: Visual chain mapping `Import → Canonical → Registry → Trust Gate → Policy`.

### 5. Status Bar Monitor
- Compact indicator in the status bar:
  ```
  🛡 SLOPGUARD: 18 ✓ | 3 ⚠ | 2 🚫
  ```
- Click to open the SLOPGUARD Control Center or launch the full web dashboard.

---

## ⚙️ Configuration Settings

| Setting | Default | Description |
|---|---|---|
| `slopguard.server.url` | `http://localhost:8000` | URL of the local or enterprise SLOPGUARD REST API. |
| `slopguard.cli.path` | `slopguard` | Path or executable name for CLI fallback mode. |
| `slopguard.autoScan` | `true` | Automatically scan active files on opening. |
| `slopguard.scanOnSave` | `true` | Automatically scan files upon saving. |
| `slopguard.policyProfile` | `STRICT_CI` | Policy gate profile (`DEVELOPMENT`, `STRICT_CI`, `ENTERPRISE`). |
| `slopguard.exclude` | `["**/node_modules/**", "**/.venv/**", ...]` | Glob patterns to ignore during workspace scans. |
| `slopguard.openDashboardAfterScan` | `false` | Automatically open the web dashboard when workspace scan finishes. |

---

## 🔒 Privacy & Security Guarantees

1. **Local-First Processing**: Code is processed locally against your own running SLOPGUARD daemon (`http://localhost:8000`) or CLI.
2. **No Third-Party Code Uploads**: Your source code is never transmitted to external cloud servers or public LLM APIs from this extension.
3. **Strict Content Security Policy (CSP)**: All Webviews run under rigid sandbox policies with script origin restrictions and zero untrusted HTML injection.
4. **Bounded Transfers**: Scans are bounded to files under 10MB to eliminate denial-of-service risks.

---

## 📦 Manual Installation via VSIX

To install the extension from a packaged `.vsix` file:

```bash
code --install-extension slopguard-0.1.0.vsix
```

---

## 🛠 Development & Building

```bash
# Clone the repository
git clone https://github.com/Vishaldubey2210/win_if_you_can.git
cd win_if_you_can/vscode-extension

# Install dependencies
npm install

# Compile TypeScript
npm run compile

# Run tests
npm test

# Package VSIX archive
npx vsce package
```

---

## 📄 License

Licensed under the [Apache License, Version 2.0](LICENSE).
