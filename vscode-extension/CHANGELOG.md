# SLOPGUARD Extension Changelog

All notable changes to the SLOPGUARD VS Code extension will be documented in this file.

## [0.1.2] - 2026-09-21

### Added & Fixed
- **Robust Cross-Platform CLI Discovery**:
  - Implemented 7-tier discovery priority (User configured `slopguard.cliPath` -> Cached -> System PATH -> Windows user Scripts `%APPDATA%\Python\Python*\Scripts\slopguard.exe` and `%LOCALAPPDATA%\Programs\Python` -> macOS/Linux `~/.local/bin`, Homebrew, pyenv, conda -> Workspace venvs -> Python interpreter `-m slopguard.cli.main`).
  - Added runtime version validation with `slopguard --version` and explicit startup logging in OutputChannel.
  - Added `slopguard.cliPath` setting for explicit executable configuration if auto-discovery fails.
- **Startup Race Fix & Scan Coordinator**:
  - Replaced ad-hoc scanning with robust state machine (`INITIALIZING`, `STARTING`, `READY`, `CLI_FALLBACK`, `OFFLINE`, `ERROR`).
  - Added pending scan queue that buffers document scans during startup and flushes them automatically upon readiness.
  - Deduplicated queued scans by document URI and latest document version/hash so no scan requests are lost or duplicated.
- **Automatic Scan Reliability**:
  - Automatic background scanning of workspace files, supported file saves, and dependency manifests (`requirements.txt`, `pyproject.toml`, `package.json`).
  - Intelligent exclusion of binary files, `.git`, `node_modules`, `.venv`, and build artifacts with debouncing and memory caching.
- **Diagnostics Pipeline & Quick Fix**:
  - Standalone `DiagnosticCollection` coexisting cleanly with Pylance and other linters.
  - Explicit diagnostic schema with Registry status, Risk level, Policy action, and Suggested fix.
  - Range mapped directly to the problematic import statement.
  - Automatic diagnostic cleanup when an import is corrected and saved.
  - Interactive Quick Fix code action to replace hallucinated dependencies with verified packages and trigger rescan.
- **Improved Status Bar Lifecycle**:
  - Added clean states: `Starting`, `Protected`, `Scanning`, `Blocked`, `Review`, `Error`.
- **Improved Error Handling & Logging**:
  - Dedicated `SLOPGUARD` OutputChannel logging all lifecycle events, discovery paths, versions, and scans without silent error swallowing.
  - Graceful REST to CLI fallback.

## [0.1.1] - 2026-09-20
- Marketplace maintenance and initial telemetry enhancements.

## [0.1.0] - 2026-09-20

### Added
- **Native VS Code Integration**: Connection to the SLOPGUARD Python Control Plane (`slopguard-ai`) via local/remote REST API and CLI fallback.
- **Inline Diagnostics**: Real-time editor squigglies powered by VS Code Diagnostics API for `BLOCK`, `HOLD`, `ALERT`, and `ALLOW` (with alias notes).
- **Quick Fixes & Code Actions**: 
  - One-click replacement of blocked typosquats with verified canonical packages.
  - Interactive rescan action.
  - Quick access to Evidence Dossiers.
- **Activity Bar & Sidebar TreeViews**:
  - **Dependency Control Plane**: Hierarchical breakdown of verified, review required, and blocked dependencies.
  - **Temporal Phantom Watchlist**: Live monitoring of unverified packages, first/last seen timestamps, observation counts, and `APPEARED` state-change alerts.
- **Status Bar Integration**: Real-time metric counter with quick access to the control center.
- **Interactive Evidence Dossier & Repair Center**:
  - Webview panel with strict Content Security Policy.
  - Visual Evidence Graph (Import → Canonical → Registry → Trust Gate → Policy).
  - Registry metadata, advisory status, repository verification, and one-click "Apply & Rescan" workflow.
- **Workspace & Single-File Scanning**:
  - Support for Python, JavaScript, TypeScript, `requirements.txt`, `pyproject.toml`, and `package.json`.
- **Zero-Trust Client Design**: Pure client architecture without duplicating core security logic in TypeScript.
