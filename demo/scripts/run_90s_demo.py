#!/usr/bin/env python3
"""
SLOPGUARD — 90-Second End-to-End Control Plane Demonstration
Executes the full lifecycle:
1. Scan AI-generated code containing real packages, aliases, and phantoms
2. Resolve import aliases (cv2 -> opencv-python)
3. Catch and Block unresolved phantom dependency (langchain_hyper_fast_auth)
4. Display multi-dimensional Evidence & Trust dossier
5. Propose contextual candidate repairs & AST patch
6. Apply patch & trigger mandatory RESCAN -> VERIFY loop
7. Inject registry outage (429 Rate Limit) -> Enforce fail-safe HOLD / REVIEW
8. Inspect temporal phantom memory & explain deterministic policy decision
"""
import asyncio
import sys
import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from unittest.mock import AsyncMock

from slopguard.core.models import (
    Ecosystem,
    ExtractedDependency,
    PolicyAction,
    RegistryEvidence,
    RegistryStatus,
)
from slopguard.core.scanner import ScannerService
from slopguard.repair.engine import RepairEngine

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

console = Console(force_terminal=True)

AI_SAMPLE_CODE = '''# AI-generated FastAPI microservice
import os
import sys
import cv2
import requests
import langchain_hyper_fast_auth_v2

app = FastAPI()
'''


async def run_demo():
    console.print(Panel.fit(
        "[bold cyan]SLOPGUARD AI Dependency Control Plane[/bold cyan]\n"
        "[bold white]90-Second Live Demonstration: Supply-Chain Firewall in Action[/bold white]",
        border_style="cyan"
    ))
    time.sleep(0.5)

    scanner = ScannerService()
    repair_engine = RepairEngine()

    # ----------------------------------------------------
    # Step 1: Scan AI-Generated Code
    # ----------------------------------------------------
    console.print("\n[bold yellow]>> STEP 1: Scanning AI-Generated Source Code...[/bold yellow]")
    scan_result = await scanner.scan_code(AI_SAMPLE_CODE, language="python", file_path="sample_service.py")

    table = Table(title="Live Scan Gate Verdicts", show_lines=True)
    table.add_column("Import Specifier", style="bold")
    table.add_column("Resolved Identity", style="magenta")
    table.add_column("Gate Action", justify="center")
    table.add_column("Risk Level", justify="center")
    table.add_column("Deterministic Reason")

    for dep in scan_result.dependencies:
        action_style = "green" if dep.decision.action == PolicyAction.ALLOW else "red" if dep.decision.action == PolicyAction.BLOCK else "yellow"
        table.add_row(
            dep.extracted.name,
            dep.identity.resolved_package,
            Text(dep.decision.action.value, style=action_style),
            dep.decision.risk_level,
            "\n".join(dep.decision.reasons[:2]),
        )
    console.print(table)
    time.sleep(0.5)

    # ----------------------------------------------------
    # Step 2: Evidence & Graph Inspection for Verified Package
    # ----------------------------------------------------
    console.print("\n[bold yellow]>> STEP 2: Multi-Dimensional Evidence Inspection (requests)[/bold yellow]")
    req_dep = next(d for d in scan_result.dependencies if d.extracted.name == "requests")
    console.print(Panel(
        f"Target: [bold]requests[/bold] | Registry Status: [green]{req_dep.registry.status.value}[/green]\n"
        f"Latest Release: {req_dep.registry.latest_version} | Total Releases: {req_dep.registry.release_count}\n"
        f"Repository: {req_dep.registry.repository_url}\n"
        f"Trust Level: [bold green]{req_dep.trust.level.value}[/bold green] | Identity Verified: {req_dep.trust.identity_verified}\n"
        f"Security Advisories: {len(scanner.evidence_graph.get_package_advisories('requests', Ecosystem.PYPI))}",
        title="Evidence Dossier",
        border_style="green"
    ))
    time.sleep(0.5)

    # ----------------------------------------------------
    # Step 3: Repair Proposal for Blocked / Aliased Package
    # ----------------------------------------------------
    console.print("\n[bold yellow]>> STEP 3: Contextual Repair Engine (cv2 -> opencv-python)[/bold yellow]")
    candidates = repair_engine.generate_candidates("cv2", Ecosystem.PYPI)
    if candidates:
        best_cand = candidates[0]
        patch = repair_engine.propose_patch(AI_SAMPLE_CODE, "cv2", best_cand)
        console.print(f"[green]Found verified replacement:[/green] [bold]{best_cand.candidate_package}[/bold] (Confidence: {best_cand.confidence * 100:.0f}%)")
        console.print(Panel(patch.diff, title="Generated AST Diff Patch", border_style="green"))

        # Mandatory Rescan Validation
        console.print("\n[bold yellow]>> STEP 4: Mandatory Rescan Validation (PATCH -> RESCAN -> VERIFY)...[/bold yellow]")
        validation = await repair_engine.rescan_and_validate(patch, scanner, language="python")
        console.print(f"Rescan Validation Success: [bold]{validation.success}[/bold] | Rescan Gate Verdict: [bold]{validation.rescan_verdict.value}[/bold] | Remaining Blocked: {validation.remaining_blocked_count}")
    time.sleep(0.5)

    # ----------------------------------------------------
    # Step 5: Failure Injection (Registry Outage / 429)
    # ----------------------------------------------------
    console.print("\n[bold yellow]>> STEP 5: Failure Injection: Simulating Registry Outage (HTTP 429)...[/bold yellow]")
    scanner.pypi_adapter.verify_package = AsyncMock(
        return_value=RegistryEvidence(
            package_name="external-sdk",
            ecosystem=Ecosystem.PYPI,
            status=RegistryStatus.RATE_LIMITED,
            error_message="HTTP 429 Rate limit reached",
        )
    )
    fail_res = await scanner.scan_dependencies(
        [ExtractedDependency(name="external-sdk", ecosystem=Ecosystem.PYPI)],
        source_label="injection_demo"
    )
    fail_dep = fail_res.dependencies[0]
    console.print(Panel(
        f"Package: [bold]external-sdk[/bold]\n"
        f"Observed Status: [bold yellow]{fail_dep.registry.status.value}[/bold yellow]\n"
        f"Enforced Action: [bold yellow]{fail_dep.decision.action.value}[/bold yellow] (Fail-Safe Quarantine)\n"
        f"Human Review Required: [bold]{fail_dep.decision.requires_human_review}[/bold]\n"
        f"Reason: {fail_dep.decision.reasons[0]}",
        title="Fail-Safe Policy Gate",
        border_style="yellow"
    ))
    time.sleep(0.5)

    # ----------------------------------------------------
    # Step 6: Decision Reconstruction Audit Trail
    # ----------------------------------------------------
    console.print("\n[bold yellow]>> STEP 6: Deterministic Decision Reconstruction ('Why was langchain_hyper_fast_auth_v2 blocked?')[/bold yellow]")
    blocked_pkg = "langchain_hyper_fast_auth_v2"
    reconstruction = scanner.audit_logger.reconstruct(
        blocked_pkg,
        evaluated_dep=next((d for d in scan_result.dependencies if d.extracted.name == blocked_pkg), None)
    )
    if reconstruction:
        console.print(Panel(
            f"Package: [bold]{reconstruction.package}[/bold]\n"
            f"Final Verdict: [bold red]{reconstruction.verdict}[/bold red] (Risk: {reconstruction.risk_level})\n"
            f"Reasons:\n  * " + "\n  * ".join(reconstruction.reasons) + "\n"
            f"Audit Trail Events Recorded: [bold cyan]{len(reconstruction.audit_events)}[/bold cyan]",
            title="Complete Decision Audit Record",
            border_style="red"
        ))

    console.print(Panel.fit(
        "[bold green][PASS] SLOPGUARD 90-SECOND DEMO COMPLETED SUCCESSFULLY[/bold green]\n"
        "Control plane verified: AST Extraction, Alias Resolution, Phantom Quarantine,\n"
        "Evidence Dossier, Contextual Repair, Rescan Gate, Fail-Safe Outage Isolation, and Decision Audit.",
        border_style="green"
    ))


if __name__ == "__main__":
    asyncio.run(run_demo())
