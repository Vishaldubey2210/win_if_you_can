# SLOPGUARD — VS Code Extension Technical Architecture

This document specifies the technical architecture, data contracts, component separation, security model, and integration flows for the **SLOPGUARD VS Code Extension**.

---

## 1. Architectural Philosophy & Boundaries

The SLOPGUARD VS Code extension is strictly a **Client & Developer Experience (DX) Layer**.

```
+--------------------------------------------------------------------------------+
|                         VS CODE EXTENSION (Client)                             |
|                                                                                |
|  [Sidebar / TreeView]   [Inline Diagnostics]   [Status Bar]   [Quick Fixes]   |
|  [Detail Webview]       [Repair Center]        [Commands]     [Settings]       |
+--------------------------------------------------------------------------------+
                                       │
                      HTTP REST / IPC  │  CLI Fallback
                                       ▼
+--------------------------------------------------------------------------------+
|                   SLOPGUARD CONTROL PLANE (Engine Source of Truth)              |
|                                                                                |
|       REST API (FastAPI)       OR       CLI Executable (slopguard)             |
|                                                                                |
|   EXTRACT → IDENTITY → VERIFY → EVIDENCE → TRUST → MEMORY → REPAIR → GATE     |
|                                                                                |
|          PyPI / NPM Registry Adapters  │  Google OSV Vulnerabilities           |
+--------------------------------------------------------------------------------+
```

### Core Invariants:
1. **Zero Duplicated Security Logic**: The extension never evaluates typosquatting, calculates trust vectors, parses ASTs, or declares security verdicts independently. All verdicts derive strictly from the backend control plane.
2. **Fail-Safe Behavior**: If the backend service is offline, the extension displays `SLOPGUARD Backend Offline` and does **not** generate false `NOT_FOUND` or `BLOCK` diagnostics.
3. **Mandatory Rescan on Quick-Fix**: Applying a repair generates a proposal, modifies the buffer, and immediately triggers the `PATCH -> RESCAN -> VERIFY` validation cycle before clearing diagnostics.
4. **Zero Untrusted Execution**: Package verification never executes untrusted code.

---

## 2. Extension Component Architecture

The extension is organized in `vscode-extension/` with modular TypeScript services:

```
vscode-extension/
├── src/
│   ├── extension.ts                    # Extension lifecycle & activation
│   ├── types/
│   │   ├── slopguard.ts                # TypeScript interfaces matching backend models
│   │   └── config.ts                   # Settings & configuration interfaces
│   ├── services/
│   │   ├── slopguardClient.ts          # High-performance async REST client (FastAPI)
│   │   ├── cliClient.ts                # Fallback subprocess CLI client (slopguard)
│   │   └── scanManager.ts              # Debounced scan coordinator, cache, and state
│   ├── providers/
│   │   ├── diagnosticsProvider.ts      # Inline squiggly diagnostics (Error, Warning, Info)
│   │   ├── dependencyTreeProvider.ts   # Activity Bar TreeView (Verified, Review, Blocked)
│   │   ├── quickFixProvider.ts         # CodeActionProvider (Apply Repair, View Evidence)
│   │   ├── statusBarProvider.ts        # Status Bar item with real-time verdict badges
│   │   └── webviewDetailProvider.ts    # Rich Webview panel for Evidence Dossier & Graph
│   └── commands/
│       ├── scanCommands.ts             # Scan Workspace, Scan Current File
│       ├── repairCommands.ts           # Find Repair, Apply Patch, Rescan
│       └── navigationCommands.ts       # Open Dashboard, Show History, Configure
├── media/                              # Icons, dark/light CSS, webview assets
├── package.json                        # Manifest, contributions, commands, settings
├── tsconfig.json                       # Modern ES2022 / Node16 compiler configuration
├── README.md                           # Developer & user documentation
└── CHANGELOG.md                        # Version history
```

---

## 3. Data Contracts & Backend Mapping

### 3.1 Backend Scan Request & Response
- **Endpoint**: `POST /api/v1/scan`
- **Request Payload**:
  ```json
  {
    "content": "import cv2\nimport requets\n",
    "language": "python",
    "source_label": "d:/Projects/app/service.py"
  }
  ```
- **Response (`ScanResult`)**:
  ```json
  {
    "scan_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
    "timestamp": "2026-09-20T12:00:00Z",
    "file_path": "d:/Projects/app/service.py",
    "summary": {
      "total_dependencies": 2,
      "allowed_count": 1,
      "hold_count": 0,
      "blocked_count": 1,
      "alert_count": 0
    },
    "dependencies": [
      {
        "extracted": {
          "name": "cv2",
          "line_number": 1,
          "ecosystem": "pypi"
        },
        "identity": {
          "raw_specifier": "cv2",
          "canonical_name": "opencv-python",
          "resolved_package": "opencv-python",
          "confidence": 0.99
        },
        "decision": {
          "action": "ALLOW",
          "risk_level": "LOW",
          "reasons": ["Package identity verified. Active releases (63) confirmed."]
        }
      },
      {
        "extracted": {
          "name": "requets",
          "line_number": 2,
          "ecosystem": "pypi"
        },
        "decision": {
          "action": "BLOCK",
          "risk_level": "HIGH",
          "reasons": ["Package 'requets' not found (HTTP 404). Potential typosquat."],
          "suggested_fix": "requests"
        }
      }
    ]
  }
  ```

### 3.2 Diagnostic Severity Mapping
Backend policy actions map deterministically to VS Code Diagnostic Severities:

| Backend Action | Risk Level | VS Code Diagnostic Severity | Inline Presentation |
|---|---|---|---|
| `BLOCK` | HIGH / CRITICAL | `vscode.DiagnosticSeverity.Error` | Red squiggly underline; blocks save/build |
| `HOLD` / `ALERT` | MEDIUM / REVIEW | `vscode.DiagnosticSeverity.Warning` | Yellow squiggly; requires developer review |
| `ALLOW` (with Alias) | LOW | `vscode.DiagnosticSeverity.Information` | Blue subtle line: `cv2 -> opencv-python` |
| `ALLOW` (Standard) | NONE | Clean (No diagnostic created) | Green badge in Sidebar TreeView |

---

## 4. Operational Modes: REST API & CLI Fallback

The extension dynamically selects the optimal client backend:

1. **Mode A (REST API — Preferred)**:
   - Queries `http://localhost:8000` (or `slopguard.server.url`).
   - Ultra-fast latency (~8ms cached, ~20ms uncached).
   - Keeps continuous persistent connection with live Evidence Graph.
2. **Mode B (CLI Fallback)**:
   - If REST API is unreachable, executes `slopguard scan <file> --json` via child process.
   - Requires no daemon server running; works completely offline with local CLI.

---

## 5. Security & Privacy Guarantees

1. **Local Analysis**: Content is sent exclusively to the configured local or enterprise endpoint (`slopguard.server.url`). No telemetry is transmitted to third parties.
2. **Input Size Limits**: Enforces a strict 10MB file limit before initiating scan requests to prevent memory exhaustion.
3. **Webview CSP**: Webview panels employ strict `Content-Security-Policy` permitting only local extension resources and preventing inline script injection.
4. **Command Injection Prevention**: CLI arguments are passed via structured argument arrays (`execFile`), never raw shell concatenation.
