# SLOPGUARD Extension Changelog

All notable changes to the SLOPGUARD VS Code extension will be documented in this file.

## [0.1.0] - 2026-09-20

### Added
- **Native VS Code Integration**: Seamless connection to the SLOPGUARD Python Control Plane (`slopguard-ai`) via local/remote REST API and CLI fallback.
- **Inline Diagnostics**: Real-time editor squigglies powered by VS Code Diagnostics API for `BLOCK`, `HOLD`, `ALERT`, and `ALLOW` (with alias notes).
- **Quick Fixes & Code Actions**: 
  - One-click replacement of blocked typosquats with verified canonical packages.
  - Interactive rescan action.
  - Quick access to Evidence Dossiers.
- **Activity Bar & Sidebar TreeViews**:
  - **Dependency Control Plane**: Hierarchical breakdown of verified, review required, and blocked dependencies with live confidence scores and policy reasons.
  - **Temporal Phantom Watchlist**: Live monitoring of unverified packages, first/last seen timestamps, observation counts, and `APPEARED` state-change alerts.
- **Status Bar Integration**: Real-time metric counter (`🛡 SLOPGUARD: X ✓ | Y ⚠ | Z 🚫`) with quick access to the control center.
- **Interactive Evidence Dossier & Repair Center**:
  - Secure Webview panel with strict Content Security Policy.
  - Visual Evidence Graph (Import → Canonical → Registry → Trust Gate → Policy).
  - Registry metadata, advisory status, repository verification, and one-click "Apply & Rescan" workflow.
- **Workspace & Single-File Scanning**:
  - Support for Python, JavaScript, TypeScript, `requirements.txt`, `pyproject.toml`, and `package.json`.
  - Configurable exclusion filters and scan-on-save debouncing.
- **Zero-Trust Client Design**: Pure client architecture without duplicating core security logic in TypeScript.
