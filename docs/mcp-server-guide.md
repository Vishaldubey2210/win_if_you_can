# SLOPGUARD Model Context Protocol (MCP) Server Guide

This guide describes how to connect and run **SLOPGUARD** as a Model Context Protocol (MCP) server with AI coding assistants, including **Claude Desktop**, **Cursor**, **Antigravity**, **VS Code**, and **Windsurf**.

---

## 1. Overview

The **SLOPGUARD MCP Server** exposes the complete AI dependency firewall directly to LLMs through standard JSON-RPC protocol tools, resources, and prompt templates.

When an AI assistant plans to write code, install libraries, or repair unresolved imports, it invokes SLOPGUARD tools to:
- Prevent dependency hallucinations before running `pip install` or `npm install`.
- Verify real package release history, provenance, and latest versions on PyPI/npm.
- Check live vulnerability advisories from OSV (Open Source Vulnerabilities).
- Block homoglyphs, typosquatting attacks, and phantom dependencies.
- Propose verified candidate repairs and enforce the mandatory **RESCAN validation gate**.

---

## 2. Quick Start

### Check Available Tools
```bash
slopguard mcp tools
```

### Get Configuration for Your Client
```bash
slopguard mcp config
```
This automatically outputs the exact, copy-pasteable JSON configuration for your current Python environment and paths.

---

## 3. Client Setup Configurations

### A. Claude Desktop
Add the following to your Claude Desktop configuration file:
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "slopguard": {
      "command": "python",
      "args": [
        "-m",
        "slopguard.mcp.server",
        "--transport",
        "stdio"
      ]
    }
  }
}
```

> **Tip:** If running in a virtual environment, replace `"python"` with the absolute path to your virtualenv's Python binary (e.g. `C:\\path\\to\\.venv\\Scripts\\python.exe`).

---

### B. Cursor
In Cursor, create `.cursor/mcp.json` in your workspace root (or configure via **Cursor Settings > Features > MCP**):

```json
{
  "mcpServers": {
    "slopguard": {
      "command": "python",
      "args": [
        "-m",
        "slopguard.mcp.server",
        "--transport",
        "stdio"
      ]
    }
  }
}
```

---

### C. Antigravity / Gemini IDE
Place `.agents/mcp_config.json` in the workspace root:

```json
{
  "mcpServers": {
    "slopguard": {
      "command": "python",
      "args": [
        "-m",
        "slopguard.mcp.server",
        "--transport",
        "stdio"
      ]
    }
  }
}
```

---

### D. Remote / Networked Clients (SSE Transport)
To run SLOPGUARD as a shared network service accessible over HTTP Server-Sent Events (SSE):

1. **Start the MCP Server on SSE mode:**
   ```bash
   slopguard mcp run --transport sse --host 127.0.0.1 --port 8001
   ```

2. **Configure your client:**
   ```json
   {
     "mcpServers": {
       "slopguard": {
         "url": "http://127.0.0.1:8001/sse"
       }
     }
   }
   ```

---

## 4. Exposed MCP Tools

| Tool Name | Parameters | Description |
| :--- | :--- | :--- |
| `verify_dependency` | `package_name` (str), `ecosystem` (pypi/npm) | Verify package existence, canonical identity, release count, and gate verdict. |
| `scan_code` | `code` (str), `language` (python/js/ts/requirements/package_json) | Scan full source file or manifest, extract all dependencies, and evaluate gate verdicts. |
| `inspect_evidence` | `package_name` (str), `ecosystem` (pypi/npm) | Retrieve detailed registry metadata, repository URL, release history, and live OSV vulnerabilities. |
| `inspect_history` | `package_name` (str), `ecosystem` (pypi/npm) | Inspect temporal phantom memory observations and transitions (e.g. `NOT_FOUND -> APPEARED`). |
| `propose_repair` | `package_name` (str), `code` (str), `ecosystem` (pypi/npm) | Generate verified candidate replacements and unified diff patches for hallucinated packages. |
| `rescan_patch` | `patched_code` (str), `language` (str) | Enforce mandatory rescan verification on a proposed patch before applying to disk. |
| `gate_install` | `package_name` (str), `ecosystem` (pypi/npm), `actor` (str) | Verify if an installation permit should be granted to an AI agent prior to running installer. |
| `list_phantoms` | *None* | List all unverified/phantom packages currently tracked in temporal memory. |
| `simulate_policy` | `package_name` (str), `ecosystem` (pypi/npm), `profile` (dev/strict_ci/enterprise) | Simulate policy engine gate decision under different risk tolerance profiles. |

---

## 5. MCP Resources & Prompts

### Resources
- `slopguard://health`: Service health and active firewall gate status.
- `slopguard://policy`: Active Policy-as-Code profile and rule evaluation matrix.
- `slopguard://phantoms`: Real-time list of temporal phantom memory entries.

### Prompts
- `audit_code_dependencies`: Pre-engineered audit instructions guiding the model to safely scan dependencies and repair vulnerabilities.
- `repair_hallucinated_dependency`: Guided prompt for generating verified repairs and validating fixes through `rescan_patch`.

---

## 6. Verification Test
You can test the MCP server in standard I/O mode using the CLI:
```bash
python -m slopguard.cli.main mcp tools
```
Or execute unit tests:
```bash
pytest tests/unit/test_mcp_server.py tests/unit/test_mcp_gateway.py -v
```
