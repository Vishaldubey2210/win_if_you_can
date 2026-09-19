from __future__ import annotations
import asyncio
import json
import sys
from pathlib import Path
from typing import Optional
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from slopguard.core.models import (
    Ecosystem,
    EvaluatedDependency,
    ExtractedDependency,
    PolicyAction,
    RegistryStatus,
)
from slopguard.core.scanner import ScannerService

console = Console()
err_console = Console(stderr=True)


@click.group()
@click.version_option(version="0.2.0", prog_name="slopguard")
def cli():
    """SLOPGUARD: AI Dependency Control Plane & Supply-Chain Firewall."""
    pass


@cli.command("scan")
@click.argument("target", type=click.Path(exists=True))
@click.option("--json-output", "--json", is_flag=True, help="Output results in JSON format.")
def scan_cmd(target: str, json_output: bool):
    """Scan a source code file or manifest for dependencies and enforce security gate."""
    scanner = ScannerService()
    path = Path(target)

    try:
        result = asyncio.run(scanner.scan_file(str(path)))
    except Exception as exc:
        err_console.print(f"[bold red]Scan failed:[/bold red] {exc}")
        sys.exit(1)

    if json_output:
        click.echo(result.model_dump_json(indent=2))
        return

    # Beautiful Rich Terminal Output
    console.print(Panel.fit(
        f"[bold cyan]SLOPGUARD AI Dependency Firewall[/bold cyan]\n"
        f"Target: [bold]{target}[/bold] | Duration: [green]{result.summary.duration_ms}ms[/green]",
        title="Security Scan Complete",
        border_style="cyan"
    ))

    table = Table(title="Dependency Control Plane Verdicts", show_lines=True)
    table.add_column("Import / Specifier", style="bold")
    table.add_column("Canonical Package", style="magenta")
    table.add_column("Registry Status", justify="center")
    table.add_column("Gate Verdict", justify="center")
    table.add_column("Risk", justify="center")
    table.add_column("Reason / Evidence")

    has_block = False

    for dep in result.dependencies:
        # Verdict color
        if dep.decision.action == PolicyAction.ALLOW:
            verdict_text = Text("ALLOW", style="bold green")
        elif dep.decision.action == PolicyAction.HOLD:
            verdict_text = Text("HOLD", style="bold yellow")
        elif dep.decision.action == PolicyAction.BLOCK:
            verdict_text = Text("BLOCK", style="bold red")
            has_block = True
        elif dep.decision.action == PolicyAction.ALERT:
            verdict_text = Text("ALERT", style="bold white on red")
            has_block = True
        else:
            verdict_text = Text(dep.decision.action.value)

        # Risk color
        risk_style = "green"
        if dep.decision.risk_level == "HIGH":
            risk_style = "red"
        elif dep.decision.risk_level == "MEDIUM":
            risk_style = "yellow"
        elif dep.decision.risk_level == "CRITICAL":
            risk_style = "bold white on red"
        risk_text = Text(dep.decision.risk_level, style=risk_style)

        reg_status = dep.registry.status.value if dep.registry else ("STDLIB" if dep.identity.is_stdlib else "N/A")
        reasons_summary = "\n".join(dep.decision.reasons)
        if dep.decision.suggested_fix:
            reasons_summary += f"\n[bold cyan]Fix:[/bold cyan] {dep.decision.suggested_fix}"

        table.add_row(
            dep.extracted.name,
            dep.identity.resolved_package,
            reg_status,
            verdict_text,
            risk_text,
            reasons_summary,
        )

    console.print(table)

    summary_panel = (
        f"[green]Allowed: {result.summary.allowed_count}[/green] | "
        f"[yellow]Hold/Review: {result.summary.hold_count}[/yellow] | "
        f"[red]Blocked: {result.summary.blocked_count}[/red] | "
        f"[bold red]Alerts: {result.summary.alert_count}[/bold red] | "
        f"Stdlib: {result.summary.stdlib_count}"
    )
    console.print(Panel(summary_panel, title="Scan Summary", border_style="dim"))

    if has_block:
        sys.exit(1)


@cli.command("verify")
@click.argument("package_name")
@click.option("--ecosystem", "-e", type=click.Choice(["pypi", "npm"], case_sensitive=False), default="pypi")
@click.option("--json-output", "--json", is_flag=True, help="Output results in JSON format.")
def verify_cmd(package_name: str, ecosystem: str, json_output: bool):
    """Verify a single package directly against registry evidence and security policy."""
    scanner = ScannerService()
    eco = Ecosystem.PYPI if ecosystem.lower() == "pypi" else Ecosystem.NPM
    adapter = scanner.pypi_adapter if eco == Ecosystem.PYPI else scanner.npm_adapter

    evidence = asyncio.run(adapter.verify_package(package_name))

    if json_output:
        click.echo(evidence.model_dump_json(indent=2))
        return

    status_color = "green" if evidence.status.value == "FOUND" else "red"
    console.print(Panel.fit(
        f"Package: [bold]{evidence.package_name}[/bold] ({evidence.ecosystem.value})\n"
        f"Status: [bold {status_color}]{evidence.status.value}[/]\n"
        f"Latency: {evidence.latency_ms:.1f}ms | Releases: {evidence.release_count}\n"
        f"Latest Version: {evidence.latest_version or 'N/A'}\n"
        f"Repository: {evidence.repository_url or 'N/A'}",
        title="Registry Verification Evidence",
        border_style="blue"
    ))


@cli.command("advisories")
@click.argument("package_name")
@click.option("--ecosystem", "-e", type=click.Choice(["pypi", "npm"], case_sensitive=False), default="pypi")
@click.option("--version", "-v", default=None, help="Specific version to query")
@click.option("--json-output", "--json", is_flag=True)
def advisories_cmd(package_name: str, ecosystem: str, version: Optional[str], json_output: bool):
    """Query live vulnerability advisories from OSV (Open Source Vulnerabilities)."""
    scanner = ScannerService()
    eco = Ecosystem.PYPI if ecosystem.lower() == "pypi" else Ecosystem.NPM
    advs, record = asyncio.run(scanner.osv_adapter.query_advisories(package_name, eco, version=version))

    if json_output:
        data = {
            "package": package_name,
            "ecosystem": eco.value,
            "version": version,
            "advisories": [a.model_dump(mode="json") for a in advs],
            "record": record.model_dump(mode="json"),
        }
        click.echo(json.dumps(data, indent=2))
        return

    if not advs:
        console.print(f"[bold green]No active advisories found on OSV for {package_name} ({eco.value}).[/bold green]")
        return

    table = Table(title=f"OSV Vulnerability Advisories: {package_name}", show_lines=True)
    table.add_column("Advisory ID", style="bold red")
    table.add_column("Severity", justify="center")
    table.add_column("Summary")
    table.add_column("Affected Versions")

    for a in advs:
        sev_color = "red" if a.severity in ("CRITICAL", "HIGH") else "yellow"
        table.add_row(
            a.advisory_id,
            Text(a.severity, style=f"bold {sev_color}"),
            a.summary,
            ", ".join(a.affected_versions) if a.affected_versions else "All versions",
        )

    console.print(table)


@cli.command("trust")
@click.argument("package_name")
@click.option("--ecosystem", "-e", type=click.Choice(["pypi", "npm"], case_sensitive=False), default="pypi")
@click.option("--json-output", "--json", is_flag=True)
def trust_cmd(package_name: str, ecosystem: str, json_output: bool):
    """Inspect multi-dimensional release trust assessment and provenance."""
    scanner = ScannerService()
    eco = Ecosystem.PYPI if ecosystem.lower() == "pypi" else Ecosystem.NPM
    adapter = scanner.pypi_adapter if eco == Ecosystem.PYPI else scanner.npm_adapter

    dep = ExtractedDependency(name=package_name, ecosystem=eco)
    identity = scanner.identity_resolver.resolve(dep)

    async def get_trust():
        registry = await adapter.verify_package(identity.resolved_package)
        advs, _ = await scanner.osv_adapter.query_advisories(identity.resolved_package, eco, version=registry.latest_version)
        prov = scanner.provenance_extractor.extract(registry)
        return scanner.trust_evaluator.evaluate(identity, registry, advs, prov), registry

    assessment, registry = asyncio.run(get_trust())

    if json_output:
        click.echo(assessment.model_dump_json(indent=2))
        return

    level_color = "green" if assessment.level.value == "VERIFIED" else "yellow" if assessment.level.value == "REVIEW" else "red"
    panel_text = (
        f"Target Package: [bold]{assessment.package_name}[/bold] ({assessment.ecosystem.value})\n"
        f"Trust Level: [bold {level_color}]{assessment.level.value}[/]\n"
        f"Identity: {'Verified' if assessment.identity_verified else 'Unverified'} | "
        f"Registry: {'Verified' if assessment.registry_verified else 'Unverified'}\n"
        f"Typosquat Risk: {'DETECTED' if assessment.has_typosquat_risk else 'None'}\n\n"
        f"[bold underline]Signals:[/bold underline]\n"
    )
    for k, v in assessment.signals.items():
        if k != "release_signals":
            panel_text += f"  - {k}: {v}\n"

    panel_text += f"\n[bold underline]Reasons:[/bold underline]\n"
    for r in assessment.reasons:
        panel_text += f"  • {r}\n"

    console.print(Panel(panel_text, title="Trust Assessment", border_style="cyan"))


@cli.command("graph")
@click.argument("package_name")
@click.option("--ecosystem", "-e", type=click.Choice(["pypi", "npm"], case_sensitive=False), default="pypi")
@click.option("--json-output", "--json", is_flag=True)
def graph_cmd(package_name: str, ecosystem: str, json_output: bool):
    """Query Evidence Graph relationships for a package."""
    scanner = ScannerService()
    eco = Ecosystem.PYPI if ecosystem.lower() == "pypi" else Ecosystem.NPM

    # Ingest package into graph
    async def build():
        adapter = scanner.pypi_adapter if eco == Ecosystem.PYPI else scanner.npm_adapter
        dep = ExtractedDependency(name=package_name, ecosystem=eco)
        identity = scanner.identity_resolver.resolve(dep)
        registry = await adapter.verify_package(identity.resolved_package)
        advs, _ = await scanner.osv_adapter.query_advisories(identity.resolved_package, eco, version=registry.latest_version)
        prov = scanner.provenance_extractor.extract(registry)
        trust = scanner.trust_evaluator.evaluate(identity, registry, advs, prov)
        decision = scanner.policy_engine.evaluate(identity, trust, registry)
        eval_dep = EvaluatedDependency(
            extracted=dep,
            identity=identity,
            registry=registry,
            trust=trust,
            decision=decision,
        )
        scanner.evidence_graph.ingest_evaluated_dependency(eval_dep, advs, prov)

    asyncio.run(build())

    releases = scanner.evidence_graph.get_package_releases(package_name, eco)
    repo = scanner.evidence_graph.get_package_repository(package_name, eco)
    advs = scanner.evidence_graph.get_package_advisories(package_name, eco)
    prov = scanner.evidence_graph.get_package_provenance(package_name, eco)

    if json_output:
        data = {
            "package": package_name,
            "ecosystem": eco.value,
            "releases": [r.model_dump(mode="json") for r in releases],
            "repository": repo.model_dump(mode="json") if repo else None,
            "advisories": [a.model_dump(mode="json") for a in advs],
            "provenance": prov.model_dump(mode="json") if prov else None,
        }
        click.echo(json.dumps(data, indent=2))
        return

    table = Table(title=f"Evidence Graph Relationships: {package_name}", show_lines=True)
    table.add_column("Relation Edge", style="bold cyan")
    table.add_column("Target Node")
    table.add_column("Type", justify="center")

    if repo:
        table.add_row("HOSTED_AT", repo.label, repo.type.value)
    for r in releases:
        table.add_row("HAS_RELEASE", r.label, r.type.value)
    for a in advs:
        table.add_row("AFFECTED_BY", a.label, a.type.value)
    if prov:
        table.add_row("ATTESTED_BY", prov.label, prov.type.value)

    console.print(table)


@cli.command("phantom")
@click.argument("action", type=click.Choice(["list", "clear"], case_sensitive=False), default="list")
@click.option("--json-output", "--json", is_flag=True)
def phantom_cmd(action: str, json_output: bool):
    """Inspect the Temporal Phantom Watchlist."""
    scanner = ScannerService()
    phantoms = scanner.memory.list_phantoms()

    if json_output:
        click.echo(json.dumps([p.model_dump(mode="json") for p in phantoms], indent=2))
        return

    if not phantoms:
        console.print("[green]No unresolved phantoms in temporal watchlist.[/green]")
        return

    table = Table(title="Temporal Phantom Watchlist", show_lines=True)
    table.add_column("Package Name", style="bold")
    table.add_column("Ecosystem")
    table.add_column("Current State", justify="center")
    table.add_column("Observations", justify="right")
    table.add_column("First Seen")
    table.add_column("Transitions")

    for p in phantoms:
        state_style = "red" if p.current_state.value == "NOT_FOUND" else "bold white on red" if p.current_state.value == "APPEARED" else "yellow"
        trans_summary = " -> ".join([t.to_state.value for t in p.transitions]) if p.transitions else "Initial"
        table.add_row(
            p.package_name,
            p.ecosystem.value,
            Text(p.current_state.value, style=state_style),
            str(p.occurrence_count),
            p.first_seen.strftime("%Y-%m-%d %H:%M:%S"),
            trans_summary,
        )

    console.print(table)


if __name__ == "__main__":
    cli()
