from __future__ import annotations
import json
from typing import Any, Dict, List, Optional
from slopguard.core.models import Ecosystem, ExtractedDependency
from slopguard.core.scanner import ScannerService
from slopguard.repair.engine import RepairEngine


class MCPGateway:
    """
    Model Context Protocol (MCP) Security Gateway.
    Exposes safe, policy-gated tools to AI agents.
    Strictly forbids any tool execution that would bypass the policy gate.
    """

    def __init__(self, scanner_service: Optional[ScannerService] = None) -> None:
        self.scanner = scanner_service or ScannerService()
        self.repair_engine = RepairEngine()

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        """Returns JSON schema definitions for MCP tools."""
        return [
            {
                "name": "verify_dependency",
                "description": "Verify package existence, canonical identity, release history, and security advisories before installation.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "package_name": {"type": "string", "description": "Package or import name"},
                        "ecosystem": {"type": "string", "enum": ["pypi", "npm"], "default": "pypi"},
                    },
                    "required": ["package_name"],
                },
            },
            {
                "name": "inspect_evidence",
                "description": "Retrieve comprehensive structured evidence and trust signals for a dependency.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "package_name": {"type": "string"},
                        "ecosystem": {"type": "string", "enum": ["pypi", "npm"], "default": "pypi"},
                    },
                    "required": ["package_name"],
                },
            },
            {
                "name": "inspect_history",
                "description": "Inspect temporal phantom memory observations and state transitions (e.g. NOT_FOUND -> APPEARED).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "package_name": {"type": "string"},
                        "ecosystem": {"type": "string", "enum": ["pypi", "npm"], "default": "pypi"},
                    },
                    "required": ["package_name"],
                },
            },
            {
                "name": "propose_repair",
                "description": "Generate candidate replacement packages and diff patches for unresolved or hallucinated dependencies.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "package_name": {"type": "string"},
                        "code": {"type": "string", "description": "Source code containing the unresolved import"},
                        "ecosystem": {"type": "string", "enum": ["pypi", "npm"], "default": "pypi"},
                    },
                    "required": ["package_name", "code"],
                },
            },
            {
                "name": "rescan_patch",
                "description": "Rescan and validate a proposed code patch through the complete control plane before applying.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "patched_code": {"type": "string"},
                        "language": {"type": "string", "default": "python"},
                    },
                    "required": ["patched_code"],
                },
            },
        ]

    async def execute_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch tool call securely."""
        eco_str = arguments.get("ecosystem", "pypi").lower()
        ecosystem = Ecosystem.PYPI if eco_str == "pypi" else Ecosystem.NPM

        if name == "verify_dependency":
            pkg = arguments["package_name"]
            dep = ExtractedDependency(name=pkg, ecosystem=ecosystem)
            res = await self.scanner.scan_dependencies([dep], source_label="mcp:verify")
            eval_dep = res.dependencies[0]
            return {
                "package": pkg,
                "verdict": eval_dep.decision.action.value,
                "risk_level": eval_dep.decision.risk_level,
                "requires_review": eval_dep.decision.requires_human_review,
                "reasons": eval_dep.decision.reasons,
                "suggested_fix": eval_dep.decision.suggested_fix,
            }

        elif name == "inspect_evidence":
            pkg = arguments["package_name"]
            adapter = self.scanner.pypi_adapter if ecosystem == Ecosystem.PYPI else self.scanner.npm_adapter
            evidence = await adapter.verify_package(pkg)
            advs, _ = await self.scanner.osv_adapter.query_advisories(pkg, ecosystem)
            return {
                "registry": evidence.model_dump(mode="json"),
                "advisories_count": len(advs),
                "advisories": [a.model_dump(mode="json") for a in advs],
            }

        elif name == "inspect_history":
            pkg = arguments["package_name"]
            rec = self.scanner.memory.get_record(pkg, ecosystem)
            if not rec:
                return {"status": "NO_PRIOR_OBSERVATIONS"}
            return rec.model_dump(mode="json")

        elif name == "propose_repair":
            pkg = arguments["package_name"]
            code = arguments["code"]
            candidates = self.repair_engine.generate_candidates(pkg, ecosystem)
            if not candidates:
                return {"candidates_found": 0, "proposals": []}
            best_cand = candidates[0]
            proposal = self.repair_engine.propose_patch(code, pkg, best_cand)
            return {
                "candidates_found": len(candidates),
                "best_candidate": best_cand.model_dump(mode="json"),
                "diff": proposal.diff,
                "patched_code": proposal.patched_code,
            }

        elif name == "rescan_patch":
            code = arguments["patched_code"]
            lang = arguments.get("language", "python")
            scan_res = await self.scanner.scan_code(code, language=lang, file_path="<mcp_rescan>")
            return {
                "allowed": scan_res.summary.blocked_count == 0,
                "blocked_count": scan_res.summary.blocked_count,
                "summary": scan_res.summary.model_dump(),
            }

        raise ValueError(f"Unknown MCP tool: {name}")
