"""
SLOPGUARD Model Context Protocol (MCP) Server.

Enables AI coding assistants (Claude Desktop, Cursor, Antigravity, VS Code,
Windsurf, Zed, etc.) to connect directly to the SLOPGUARD security firewall
to verify packages, scan code, inspect evidence, inspect temporal phantom memory,
propose patches, rescan repairs, and check installation gates.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List, Optional

from mcp.server.mcpserver import MCPServer
from slopguard import __version__
from slopguard.core.scanner import ScannerService
from slopguard.mcp.gateway import MCPGateway


def create_mcp_server(scanner_service: Optional[ScannerService] = None) -> MCPServer:
    """Create and configure the SLOPGUARD MCPServer instance."""
    scanner = scanner_service or ScannerService()
    gateway = MCPGateway(scanner_service=scanner)

    server = MCPServer(
        name="slopguard",
        version=__version__,
        instructions=(
            "SLOPGUARD is an AI Dependency Control Plane & Supply-Chain Firewall. "
            "Use these tools to verify packages before installing or importing them, "
            "scan code snippets for hallucinated or malicious packages, "
            "propose repairs for hallucinated imports, and validate safe diff patches."
        ),
    )

    # -------------------------------------------------------------------------
    # Tools
    # -------------------------------------------------------------------------

    @server.tool(
        name="verify_dependency",
        description=(
            "Verify package existence, canonical identity, release history, "
            "and security policy gate verdict before installation or import."
        ),
    )
    async def verify_dependency(
        package_name: str,
        ecosystem: str = "pypi",
    ) -> Dict[str, Any]:
        """Verify package against registry existence and policy gate."""
        return await gateway.execute_tool(
            "verify_dependency",
            {"package_name": package_name, "ecosystem": ecosystem},
        )

    @server.tool(
        name="scan_code",
        description=(
            "Scan full source code or manifest (requirements.txt, package.json, python, js, ts) "
            "and evaluate all extracted dependencies through the security gate."
        ),
    )
    async def scan_code(
        code: str,
        language: str = "python",
    ) -> Dict[str, Any]:
        """Extract and evaluate dependencies from source code or manifest."""
        return await gateway.execute_tool(
            "scan_code",
            {"code": code, "language": language},
        )

    @server.tool(
        name="inspect_evidence",
        description=(
            "Retrieve comprehensive structured evidence (registry releases, repository url, "
            "upload timestamps, and live OSV vulnerability advisories) for a package."
        ),
    )
    async def inspect_evidence(
        package_name: str,
        ecosystem: str = "pypi",
    ) -> Dict[str, Any]:
        """Retrieve full registry evidence and vulnerability advisories."""
        return await gateway.execute_tool(
            "inspect_evidence",
            {"package_name": package_name, "ecosystem": ecosystem},
        )

    @server.tool(
        name="inspect_history",
        description=(
            "Inspect temporal phantom memory observations and state transitions "
            "(e.g. NOT_FOUND -> APPEARED or occurrence counts) for a package."
        ),
    )
    async def inspect_history(
        package_name: str,
        ecosystem: str = "pypi",
    ) -> Dict[str, Any]:
        """Inspect temporal phantom memory observations."""
        return await gateway.execute_tool(
            "inspect_history",
            {"package_name": package_name, "ecosystem": ecosystem},
        )

    @server.tool(
        name="propose_repair",
        description=(
            "Generate candidate replacement packages and diff patches for "
            "unresolved, hallucinated, or typosquatted dependencies."
        ),
    )
    async def propose_repair(
        package_name: str,
        code: str,
        ecosystem: str = "pypi",
    ) -> Dict[str, Any]:
        """Generate candidate replacements and patch proposals."""
        return await gateway.execute_tool(
            "propose_repair",
            {"package_name": package_name, "code": code, "ecosystem": ecosystem},
        )

    @server.tool(
        name="rescan_patch",
        description=(
            "Rescan and validate a proposed code patch through the complete "
            "control plane before applying it to the codebase."
        ),
    )
    async def rescan_patch(
        patched_code: str,
        language: str = "python",
    ) -> Dict[str, Any]:
        """Enforce the mandatory rescan verification gate on a patch."""
        return await gateway.execute_tool(
            "rescan_patch",
            {"patched_code": patched_code, "language": language},
        )

    @server.tool(
        name="gate_install",
        description=(
            "Evaluate an installation permit for an AI agent before running "
            "pip install or npm install. Returns permit status and reasons."
        ),
    )
    async def gate_install(
        package_name: str,
        ecosystem: str = "pypi",
        actor: str = "ai-agent",
    ) -> Dict[str, Any]:
        """Verify package against firewall install policy."""
        return await gateway.execute_tool(
            "gate_install",
            {"package_name": package_name, "ecosystem": ecosystem, "actor": actor},
        )

    @server.tool(
        name="list_phantoms",
        description="List all unresolved phantom/hallucinated dependencies currently tracked in memory.",
    )
    async def list_phantoms() -> Dict[str, Any]:
        """List active phantom memory records."""
        return await gateway.execute_tool("list_phantoms", {})

    @server.tool(
        name="simulate_policy",
        description=(
            "Simulate policy gate action for a package under a specific profile "
            "(development, strict_ci, enterprise)."
        ),
    )
    async def simulate_policy(
        package_name: str,
        ecosystem: str = "pypi",
        profile: str = "strict_ci",
    ) -> Dict[str, Any]:
        """Simulate policy evaluation without changing state."""
        return await gateway.execute_tool(
            "simulate_policy",
            {"package_name": package_name, "ecosystem": ecosystem, "profile": profile},
        )

    # -------------------------------------------------------------------------
    # Resources
    # -------------------------------------------------------------------------

    @server.resource("slopguard://health", description="SLOPGUARD health and service status")
    def health_resource() -> str:
        return json.dumps({
            "status": "healthy",
            "service": "slopguard",
            "version": __version__,
            "quarantine_gate": "active",
        }, indent=2)

    @server.resource("slopguard://policy", description="Active security policy rules and profiles")
    def policy_resource() -> str:
        return json.dumps({
            "current_profile": scanner.policy_engine.config.profile.value,
            "rules": {k: v.value for k, v in scanner.policy_engine.config.rules.items()},
        }, indent=2)

    @server.resource("slopguard://phantoms", description="Current temporal phantom dependency watchlist")
    def phantoms_resource() -> str:
        phantoms = scanner.memory.list_phantoms()
        return json.dumps([p.model_dump(mode="json") for p in phantoms], indent=2)

    # -------------------------------------------------------------------------
    # Prompts
    # -------------------------------------------------------------------------

    @server.prompt(
        name="audit_code_dependencies",
        description="Prompt template to audit all imports and dependencies in a source file or snippet",
    )
    def audit_code_dependencies_prompt(file_path: str, code_snippet: str) -> str:
        return (
            f"You are conducting a strict dependency security audit of the following code from `{file_path}`:\n\n"
            f"```\n{code_snippet}\n```\n\n"
            "Please use the `scan_code` tool to evaluate all imports. For any blocked or warning verdicts:\n"
            "1. Explain why the dependency was flagged (hallucination, typosquat, vulnerable advisory, phantom).\n"
            "2. Use `propose_repair` to find verified replacement packages.\n"
            "3. Use `rescan_patch` to validate that the proposed fix passes the security gate before applying."
        )

    @server.prompt(
        name="repair_hallucinated_dependency",
        description="Prompt template to replace a hallucinated or unverified import with a safe alternative",
    )
    def repair_hallucinated_dependency_prompt(package_name: str, code_snippet: str) -> str:
        return (
            f"The package `{package_name}` was flagged by SLOPGUARD as hallucinated or non-existent.\n"
            f"Here is the context code:\n\n"
            f"```\n{code_snippet}\n```\n\n"
            f"Use the `propose_repair` tool for `{package_name}` to find real canonical packages, "
            f"apply the diff, and call `rescan_patch` to verify the patched code passes all gates."
        )

    return server


def run_mcp_server(
    transport: str = "stdio",
    host: str = "127.0.0.1",
    port: int = 8001,
) -> None:
    """Run the SLOPGUARD MCP Server using the specified transport."""
    server = create_mcp_server()
    if transport == "stdio":
        server.run(transport="stdio")
    elif transport in ("sse", "http"):
        server.run(transport="sse", host=host, port=port)
    else:
        raise ValueError(f"Unsupported transport: {transport}. Choose 'stdio' or 'sse'.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run SLOPGUARD Model Context Protocol (MCP) Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="Transport protocol (default: stdio)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind for SSE transport (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8001,
        help="Port to bind for SSE transport (default: 8001)",
    )
    args = parser.parse_args()
    run_mcp_server(transport=args.transport, host=args.host, port=args.port)
